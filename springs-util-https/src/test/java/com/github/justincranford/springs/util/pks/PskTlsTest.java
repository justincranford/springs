package com.github.justincranford.springs.util.pks;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.assertj.core.api.Assertions;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.PSKTlsClient;
import org.bouncycastle.tls.PSKTlsServer;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SuppressWarnings({"nls", "static-method", "hiding", "resource"})
public class PskTlsTest {
	private static final Logger log = LoggerFactory.getLogger(PskTlsTest.class);
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final int[] CIPHER_SUITES = new int[] { CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA };
	private static final TlsPskIdentity PSK_IDENTITY = new TlsPskIdentity("identity".getBytes(StandardCharsets.UTF_8),"secret".getBytes(StandardCharsets.UTF_8));

    @ParameterizedTest // repeat test, use unique port each time to avoid TCP CLOSE_WAIT
    @ValueSource(ints={9440, 9441, 9442, 9443, 9444, 9445, 9446, 9447, 9448, 9449})
    @Order(1)
    public void testPlaintext(final int port) throws Exception {
        doClientServer(false, "localhost", port);
    }

    @ParameterizedTest // repeat test, use unique port each time to avoid TCP CLOSE_WAIT
    @ValueSource(ints={8440, 8441, 8442, 8443, 8444, 8445, 8446, 8447, 8448, 8449})
    @Order(2)
    public void testTlsPsk(final int port) throws Exception {
        doClientServer(true, "localhost", port);
    }

    // Start server, send message with client, and verify client received echo of its request
    // useTlsPsk=true uses plaintext communication
    // useTlsPsk=true uses plaintext communication
	private void doClientServer(final boolean useTlsPsk, final String address, final int port) throws Exception {
		final PskTlsServer pskTlsServer = Mockito.spy(new PskTlsServer(useTlsPsk, address, port, 2));
		final String clientRequest = "This is an echo test " + SECURE_RANDOM.nextInt();
		final Thread serverThread = pskTlsServer.start();

		final String serverResponse = PskTlsClient.send(useTlsPsk, address, port, clientRequest);
        Assertions.assertThat(serverResponse).isEqualTo(clientRequest);

        serverThread.interrupt();
	}

	public static class PskTlsClient {
	    public static String send(final boolean useTlsPsk, final String address, final int port, final String clientRequest) throws Exception {
	        log.info("Client: Connecting to server port " + port);
			try (final Socket socket = new Socket(address, port)) {
	            log.info("Client: Connected to server port " + port);
	            final InputStream inputStream = socket.getInputStream();
				final OutputStream outputStream = socket.getOutputStream();

				final byte[] serverResponseBytes = new byte[clientRequest.length()];
				if (useTlsPsk) { // TLS PSK send and receive
					final TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(inputStream, outputStream);
					tlsClientProtocol.connect(new PSKTlsClient(new BcTlsCrypto(SECURE_RANDOM), PSK_IDENTITY) {
					    @Override public int[] getCipherSuites() { return CIPHER_SUITES; }
					});

					final OutputStream tlsOutputStream = tlsClientProtocol.getOutputStream();
					log.info("Client: Sending \"Hello from PSK Client\"");
					tlsOutputStream.write(clientRequest.getBytes(StandardCharsets.UTF_8));
					tlsOutputStream.flush();

					final InputStream tlsInputStream = tlsClientProtocol.getInputStream();
					final int numServerResponseBytes = tlsInputStream.read(serverResponseBytes);
	                Assertions.assertThat(numServerResponseBytes).isEqualTo(clientRequest.length());

					tlsClientProtocol.close();
				} else { // PLAINTEXT send and receive
	                log.info("Client: Sending \"Hello from PSK Client\"");
	                outputStream.write(clientRequest.getBytes(StandardCharsets.UTF_8));
	                outputStream.flush();

	                final int numServerResponseBytes = inputStream.read(serverResponseBytes);
	                Assertions.assertThat(numServerResponseBytes).isEqualTo(clientRequest.length());
				}
                final String serverResponse = new String(serverResponseBytes, StandardCharsets.UTF_8);
				log.info("Client: Received from server: " + serverResponse);
				return serverResponse;
	        }
	    }
	}
	public static class PskTlsServer {
		private static final int MAX_WAIT_MILLIS = 3000;
		private final boolean useTlsPsk;
		private final String address;
		private final int port;
		private final int backlog;

		public PskTlsServer(final boolean useTlsPsk, final String address, final int port, final int backlog) {
			this.useTlsPsk = useTlsPsk;
			this.address = address;
			this.port = port;
			this.backlog = backlog;
		}
		public void listen(final CountDownLatch countDownLatch) throws Exception {
	        try (ServerSocket serverSocket = new ServerSocket(this.port, this.backlog, InetAddress.getByName(this.address))) {
	            log.info("Server: Listening on " + this.address + ":" + this.port + "...");
	            countDownLatch.countDown(); // signal to main thread that server started OK
	            while (true) {
	                log.info("Server: While loop");
	                try (final Socket socket = serverSocket.accept()) {
	                    log.info("Server: Accepted connection from client");
    					final InputStream inputStream = socket.getInputStream();
						final OutputStream outputStream = socket.getOutputStream();

						if (this.useTlsPsk) { // TLS PSK echo
							final TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(inputStream, outputStream);
	    					final BcTlsCrypto bcTlsCrypto = new BcTlsCrypto(SECURE_RANDOM);
							final PSKTlsServer pskTlsServer = new PSKTlsServer(bcTlsCrypto, new TlsPskIdentityManager(PSK_IDENTITY)) {
	    					    @Override public int[] getCipherSuites() { return CIPHER_SUITES; }
	    					};
							tlsServerProtocol.accept(pskTlsServer);

	    					final InputStream tlsInputStream = tlsServerProtocol.getInputStream();
							final OutputStream tlsOutputStream = tlsServerProtocol.getOutputStream();
							Streams.pipeAll(tlsInputStream, tlsOutputStream);
						} else { // PLAINTEXT echo
							Streams.pipeAll(inputStream, outputStream);
						}
	                }
	            }
	        }
	    }
		public Thread start() {
			final CountDownLatch countDownLatch = new CountDownLatch(1);
			final Thread serverThread = new Thread(() -> {
	            try {
	                this.listen(countDownLatch);
	            } catch (Exception e) {
	    			log.info("Main: Exception while listening", e);
	            }
	        });
			log.info("Main: Waiting for Server");
			final long nanos = System.nanoTime();
	        serverThread.start();
	        try {
				countDownLatch.await(MAX_WAIT_MILLIS, TimeUnit.MILLISECONDS); // wait for server thread to indicate it started OK
//				Thread.sleep(100); // waiting for server to call serverSocket.accept() doesn't seem to help
			} catch (InterruptedException e) {
    			log.info("Main: Exception while waiting for start", e);
				throw new RuntimeException(e);
			} finally {
				log.info("Main: Waited for Server start for " + Float.valueOf((System.nanoTime() - nanos)/1000000F) + " msec");
			}
			return serverThread;
		}
	}

	public static class TlsPskIdentity implements TlsPSKIdentity {
        private final byte[] identity;
        private final byte[] psk;
        public TlsPskIdentity(final byte[] pskIdentity, final byte[] psk) {
        	this.identity = pskIdentity;
        	this.psk = psk;
        }
	    @Override public byte[] getPSKIdentity() { return this.identity.clone(); }
	    @Override public byte[] getPSK() { return this.psk.clone(); }
		@Override public void skipIdentityHint() { /*do nothing*/ }
		@Override public void notifyIdentityHint(byte[] psk_identity_hint) { /*do nothing*/ }
	}

	public static class TlsPskIdentityManager implements TlsPSKIdentityManager {
		private final TlsPskIdentity tlsPskIdentity;
		public TlsPskIdentityManager(final TlsPskIdentity tlsPskIdentity) { this.tlsPskIdentity = tlsPskIdentity; }
	    @Override
	    public byte[] getHint() { return this.tlsPskIdentity.getPSKIdentity(); }
	    @Override
	    public byte[] getPSK(byte[] identity) { return this.tlsPskIdentity.getPSK(); }
	}
}
