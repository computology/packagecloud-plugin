package org.jenkinsci.plugins.packagecloud;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.*;
import hudson.model.*;
import hudson.model.Result;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.packagecloud.client.*;
import io.packagecloud.client.Package;
import org.apache.commons.io.IOUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.text.SimpleDateFormat;
import java.util.Calendar;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * The type Artifact publisher.
 */
public class ArtifactPublisher extends Notifier {

    private final String repository;
    private final String username;
    private final String distro;
    private final String hostname;
    private final String port;
    private final Boolean verbose;
    private final String protocol;
    private final String repositoryOwner;

    /**
     * Instantiates a new Artifact publisher.
     *
     * @param username the username
     * @param repository the repository
     * @param distro the distro
     * @param hostname the hostname
     * @param port the port
     * @param protocol the protocol
     * @param repositoryOwner the repository owner (for collab)
     * @param verbose if verbose
     */
// Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public ArtifactPublisher(String username, String repository, String distro, String hostname, String port, String protocol, String repositoryOwner, Boolean verbose) {
        this.username = username;
        this.repository = repository;
        this.distro = distro;
        this.hostname = hostname;
        this.port = port;
        this.verbose = verbose;
        this.protocol = protocol;
        this.repositoryOwner = repositoryOwner;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     * @return the repository
     */
    public String getRepository() {
        return this.repository;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     * @return the repository owner
     */
    public String getRepositoryOwner() {
        return this.repositoryOwner;
    }

    /**
     * Gets distro.
     *
     * @return the distro
     */
    public String getDistro() {
        return this.distro;
    }

    /**
     * Gets username.
     *
     * @return the username
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * Gets hostname.
     *
     * @return the hostname
     */
    public String getHostname() { return this.hostname; }

    public String getPort() {
        return this.port;
    }

    public String getProtocol() {
        return this.protocol;
    }

    public Boolean getVerbose() {
        return this.verbose;
    }

    /**
     * Hold an instance of the Descriptor implementation of this publisher.
     */
    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.BUILD;
    }

    /**
     * Is supported package.
     *
     * @param filename the filename
     * @return the boolean
     */
    public boolean isSupportedPackage(String filename){
        boolean result = false;
        for (String ext: Package.getSupportedExtensions()){
            if(filename.endsWith(ext)){
               result = true;
            }
        }
        return result;
    }

    private String logFormat(String message){
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        String date = sdf.format(cal.getTime());
        return String.format("%s [org.jenkinsci.plugins.packagecloud.ArtifactPublisher] %s", date, message);
    }

    private void logger(BuildListener listener, String message){
        listener.getLogger().println(logFormat(message));
    }

    private void verboseLogger(BuildListener listener, String message){
        if (this.verbose){
            logger(listener, message);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @param build
     * @param launcher
     * @param listener
     * @return
     * @throws InterruptedException
     * @throws IOException
     *           {@inheritDoc}
     */
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        verboseLogger(listener, "Verbose Logging Enabled");

        PackageCloudHelper packageCloudHelper = new PackageCloudHelper();

        if (build.getResult() == Result.FAILURE || build.getResult() == Result.ABORTED) {
            // build failed. don't post
            return true;
        }

        verboseLogger(listener, String.format("Build Status: %s", build.getResult().toString()));

        EnvVars envVars = build.getEnvironment(listener);

        logger(listener, String.format("Job configured with: { repo: %s, distro: %s, username: %s }",
                getRepository(),
                getDistro(),
                getUsername()));

        Collection<Fingerprint> buildFingerprints = build.getBuildFingerprints();

        verboseLogger(listener, String.format("Fingerprinting: found %d fingerprints", buildFingerprints.size()));

        UsernamePasswordCredentials credentials = packageCloudHelper.getCredentialsForUser(this.getUsername(), this.getHostname());

        Connection connection = packageCloudHelper.getConnectionForHostAndPort(this.getHostname(), this.getPort(), this.getProtocol());
        PackageCloud packageCloud = packageCloudHelper.configuredClient(credentials, connection);

        List<Fingerprint> rejectedFingerprints = new ArrayList<Fingerprint>();
        List<Package> packagesToUpload = new ArrayList<Package>();

        // first pass: separate valid packages from non supported packages
        findValidPackages(build, listener, envVars, buildFingerprints, rejectedFingerprints, packagesToUpload);

        // second pass: hydrate any detected dsc's with their respective sourceFiles
        hydrateDebianSourcePackages(build, listener, envVars, packageCloud, rejectedFingerprints, packagesToUpload);

        // final phase: upload all packages
        uploadAllPackages(build, listener, packageCloud, packagesToUpload);

        verboseLogger(listener, "Done");
        return true;
    }

    private void uploadAllPackages(AbstractBuild<?, ?> build, BuildListener listener, PackageCloud packageCloud, List<Package> packagesToUpload) {
        verboseLogger(listener, "Uploading packages (uploadAllPackages)");

        for (Package pkg : packagesToUpload) {
            try {
                verboseLogger(listener, String.format("Uploading package: %s...", pkg.getFilename()));
                if (getRepositoryOwner() == null || getRepositoryOwner().isEmpty()) {
                    packageCloud.putPackage(pkg);
                } else {
                    packageCloud.putPackage(pkg, repositoryOwner);
                }
                verboseLogger(listener, String.format("Finished uploading package: %s", pkg.getFilename()));
            } catch (Exception e) {
                build.setResult(Result.FAILURE);
                logger(listener, "ERROR  " + e.getMessage());
            }
        }
    }

    private void hydrateDebianSourcePackages(AbstractBuild<?, ?> build, BuildListener listener, EnvVars envVars, PackageCloud packageCloud, List<Fingerprint> rejectedFingerprints, List<Package> packagesToUpload) throws IOException {
        for (Package pkg : packagesToUpload) {
            if(pkg.getFilename().endsWith("dsc")){
                hydrateDebianSourcePackage(build, listener, envVars, packageCloud, rejectedFingerprints, pkg);
            }
        }
    }

    private void hydrateDebianSourcePackage(AbstractBuild<?, ?> build, BuildListener listener, EnvVars envVars, PackageCloud packageCloud, List<Fingerprint> rejectedFingerprints, Package pkg) throws IOException {
        Map<String, InputStream> sourceFiles = new HashMap<String, InputStream>();
        logger(listener, "Detected dsc (debian source) file");
        try {
            pkg.getFilestream().mark(0);
            Contents contents = packageCloud.packageContents(pkg);
            // find the files we need from the rejected fingerprints
            for (File file : contents.files) {
                for (Fingerprint fin : rejectedFingerprints) {
                    if (fin.getDisplayName().equals(file.filename)){
                        logger(listener, "found dsc component " + fin.getDisplayName());
                        String expanded = Util.replaceMacro(fin.getFileName(), envVars);
                        FilePath filePath = new FilePath(build.getWorkspace(), expanded);
                        sourceFiles.put(fin.getDisplayName(), filePath.read());
                    }
                }

            }
        } catch (Exception e) {
            build.setResult(Result.FAILURE);
            logger(listener, "ERROR  " + e.getMessage());
        }
        pkg.getFilestream().reset();
        pkg.setSourceFiles(sourceFiles);
    }

    private void findValidPackages(AbstractBuild<?, ?> build, BuildListener listener, EnvVars envVars, Collection<Fingerprint> buildFingerprints, List<Fingerprint> rejectedFingerprints, List<Package> packagesToUpload) throws IOException {
        verboseLogger(listener, "Finding valid Packages (findValidPackages)");
        for (Fingerprint fin : buildFingerprints) {
            if(isSupportedPackage(fin.getDisplayName())){
                logger(listener, "Processing: " + fin.getDisplayName());
                String expanded = Util.replaceMacro(fin.getFileName(), envVars);
                FilePath filePath = new FilePath(build.getWorkspace(), expanded);

                if (fin.getDisplayName().endsWith("dsc")) {
                    Package p = new Package(fin.getDisplayName(), IOUtils.toByteArray(filePath.read()), this.getRepository(), Integer.valueOf(this.getDistro()));
                    p.setFilename(fin.getDisplayName());
                    verboseLogger(listener, String.format("Adding DSC: %s to packages to upload", fin.getDisplayName()));
                    packagesToUpload.add(p);
                } else if (this.getDistro().equals("gem")){
                    Package p = new Package(fin.getDisplayName(), IOUtils.toByteArray(filePath.read()), this.getRepository());
                    p.setFilename(fin.getDisplayName());
                    verboseLogger(listener, String.format("Adding GEM: %s to packages to upload", fin.getDisplayName()));
                    packagesToUpload.add(p);
                } else {
                    Package p = new Package(fin.getDisplayName(), filePath.read(), this.getRepository(), Integer.valueOf(this.getDistro()));
                    p.setFilename(fin.getDisplayName());
                    verboseLogger(listener, String.format("Adding %s to packages to upload with Distro: %s", fin.getDisplayName(), this.getDistro()));
                    packagesToUpload.add(p);
                }
            } else {
                rejectedFingerprints.add(fin);
            }
        }
    }

    /**
     * BuildStepDescriptor
     */
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        PackageCloudHelper packageCloudHelper = new PackageCloudHelper();

        /**
         * The default constructor.
         */
        public DescriptorImpl() {
            super(ArtifactPublisher.class);
            load();
        }

        /**
         * The name of the plugin to display them on the project configuration web page.
         *
         * {@inheritDoc}
         *
         * @return {@inheritDoc}
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        @JavaScriptMethod
        public String getDisplayName() {
            return "Push to packagecloud.io";
        }

        /**
         * Return the location of the help document for this publisher.
         *
         * {@inheritDoc}
         *
         * @return {@inheritDoc}
         * @see hudson.model.Descriptor#getHelpFile()
         */
        @Override
        public String getHelpFile() {
            return "/plugin/packagecloud/help.html";
        }

        /**
         * Returns true if this task is applicable to the given project.
         *
         * {@inheritDoc}
         *
         * @return {@inheritDoc}
         * @see hudson.model.AbstractProject.AbstractProjectDescriptor#isApplicable(Descriptor)
         */
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        /**
         * Validates we can find credentials for this username
         *
         * @param value the username
         * @param hostname the hostname
         * @return validation result
         */
        public FormValidation doCheckUsername(@QueryParameter String value, @QueryParameter String hostname) {
            if (packageCloudHelper.getCredentialsForUser(value, hostname) == null) {
                return FormValidation.error(String.format("Can't find %s credentials for this username", hostname));
            } else {
                return FormValidation.ok();
            }
        }

        private ListBoxModel findDistroItems(UsernamePasswordCredentials credentials, Connection connection) throws Exception {
            PackageCloud packageCloud = packageCloudHelper.configuredClient(credentials, connection);
            ListBoxModel items = new ListBoxModel();

            Distributions distributions = packageCloud.getDistributions();

            items.add("Gem", "gem");

            for (Distribution dist : distributions.py) {
                for (Version version : dist.versions) {
                    items.add(dist.displayName + " (" + version.displayName + ")", String.valueOf(version.id));
                }
            }
            for (Distribution dist : distributions.rpm) {
                for (Version version : dist.versions) {
                    items.add(dist.displayName + " (" + version.displayName + ")", String.valueOf(version.id));
                }
            }
            for (Distribution dist : distributions.deb) {
                for (Version version : dist.versions) {
                    items.add(dist.displayName + " (" + version.displayName + ")", String.valueOf(version.id));
                }
            }
            return items;
        }

        /**
         * Fills out the distributions dropdown.
         *
         * Since the username is not known (or needed) to retrieve distributions, we iterate through all available credentials
         * until we find a working token.
         *
         * @param hostname the hostname
         * @param port the port
         * @param protocol the protocol
         * @param username the username
         * @return the list box model
         */
        public ListBoxModel doFillDistroItems(@QueryParameter("hostname") String hostname,
                                              @QueryParameter("port") String port,
                                              @QueryParameter("protocol") String protocol,
                                              @QueryParameter("username") String username) throws Exception {

            if (username.equals("")){
                ListBoxModel items = new ListBoxModel();
                items.add("Please enter username to load distributions", "-1");
                return items;
            } else {
                UsernamePasswordCredentials credentials = packageCloudHelper.getCredentialsForUser(username, hostname);
                if(credentials == null){
                    ListBoxModel items = new ListBoxModel();
                    items.add(String.format("Couldn't find credentials for %s@%s", username, hostname));
                    return items;
                } else {
                    Connection connection = packageCloudHelper.getConnectionForHostAndPort(hostname, port, protocol);
                    return findDistroItems(credentials, connection);
                }
            }
        }
    }
}

