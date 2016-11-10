package org.jenkinsci.plugins.packagecloud;

import hudson.model.BuildListener;
import io.packagecloud.client.interfaces.ProgressListener;

public class ProgressLogger implements ProgressListener {

    private final BuildListener buildListener;

    public ProgressLogger(BuildListener buildListener) {
       this.buildListener = buildListener;
    }

    @Override
    public void update(long bytes, String filename) {
        String formattedString = String.format("%s: Sent %d bytes", filename, bytes);
        buildListener.getLogger().println(ArtifactPublisher.logFormat(formattedString));
    }
}
