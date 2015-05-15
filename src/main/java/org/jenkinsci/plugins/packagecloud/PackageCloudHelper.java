package org.jenkinsci.plugins.packagecloud;


import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.HostnameRequirement;
import hudson.security.ACL;
import io.packagecloud.client.Client;
import io.packagecloud.client.Connection;
import io.packagecloud.client.Credentials;
import io.packagecloud.client.PackageCloud;
import jenkins.model.Jenkins;

import java.util.List;

/**
 * Helper for interacting with the PackageCloud client library
 */
public class PackageCloudHelper {

    /**
     * Gets credentials.
     *
     * @return the credentials
     */
    public List<UsernamePasswordCredentials> getCredentials(String domain) {
        return CredentialsProvider.lookupCredentials(
                UsernamePasswordCredentials.class,
                Jenkins.getInstance(),
                ACL.SYSTEM,
                new HostnameRequirement(domain));
    }

    /**
     * Gets credentials.
     *
     * @return the credentials
     */
    public List<UsernamePasswordCredentials> getCredentials() {
        return getCredentials("packagecloud.io");
    }

    /**
     * Gets credentials for user.
     *
     * @param username the username
     * @return the credentials for user
     */
    public UsernamePasswordCredentials getCredentialsForUser(String username, String domain) {
        UsernamePasswordCredentials matchingCred = null;

        for(UsernamePasswordCredentials cred : getCredentials(domain)){
            if(cred.getUsername().equals(username)){
                matchingCred = cred;
            }
        }
        return matchingCred;
    }

    public Connection getConnectionForHostAndPort(String hostname, String port, String protocol){
        return new Connection(hostname, Integer.valueOf(port), protocol);
    }

    public Connection getDefaultConnection() {
        return getConnectionForHostAndPort("packagecloud.io", "443", "https");
    }

    /**
     * Configured client.
     *
     * @param creds the creds
     * @return the package cloud
     */
    public PackageCloud configuredClient(UsernamePasswordCredentials creds, Connection connection){
        Credentials pcloudCreds = new Credentials(creds.getUsername(), creds.getPassword().getPlainText());
        return new PackageCloud(new Client(pcloudCreds, connection));
    }

}
