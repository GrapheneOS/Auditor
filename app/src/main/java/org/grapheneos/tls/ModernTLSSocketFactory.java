package org.grapheneos.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class ModernTLSSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory wrapped;

    public ModernTLSSocketFactory() {
        try {
            final SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            wrapped = context.getSocketFactory();
        } catch (final KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return wrapped.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return wrapped.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return configureSocket(wrapped.createSocket());
    }

    @Override
    public Socket createSocket(final Socket s, final String host, final int port,
            final boolean autoClose) throws IOException {
        return configureSocket(wrapped.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket(final String host, final int port)
            throws IOException, UnknownHostException {
        return configureSocket(wrapped.createSocket(host, port));
    }

    @Override
    public Socket createSocket(final String host, final int port, final InetAddress localHost,
            final int localPort) throws IOException, UnknownHostException {
        return configureSocket(wrapped.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(final InetAddress host, final int port) throws IOException {
        return configureSocket(wrapped.createSocket(host, port));
    }

    @Override
    public Socket createSocket(final InetAddress address, final int port,
            final InetAddress localAddress, final int localPort) throws IOException {
        return configureSocket(wrapped.createSocket(address, port, localAddress, localPort));
    }

    private static Socket configureSocket(final Socket socket) {
        ((SSLSocket) socket).setEnabledProtocols(new String[] {"TLSv1.3"});
        return socket;
    }
}
