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
    public List<UsernamePasswordCredentials> getCredentials() {
        return CredentialsProvider.lookupCredentials(
                UsernamePasswordCredentials.class,
                Jenkins.getInstance(),
                ACL.SYSTEM,
                new HostnameRequirement("packagecloud.io"));
    }

    /**
     * Gets credentials for user.
     *
     * @param username the username
     * @return the credentials for user
     */
    public UsernamePasswordCredentials getCredentialsForUser(String username) {
        UsernamePasswordCredentials matchingCred = null;

        for(UsernamePasswordCredentials cred : getCredentials()){
            if(cred.getUsername().equals(username)){
                matchingCred = cred;
            }
        }
        return matchingCred;
    }

    /**
     * Configured client.
     *
     * @param creds the creds
     * @return the package cloud
     */
    public PackageCloud configuredClient(UsernamePasswordCredentials creds){
        Credentials pcloudCreds = new Credentials(creds.getUsername(), creds.getPassword().getPlainText());
        return new PackageCloud(new Client(pcloudCreds));
    }

}
