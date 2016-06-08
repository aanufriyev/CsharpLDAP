/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
* 
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
* copies of the Software, and to  permit persons to whom the Software is 
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in 
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/
//
// Novell.Directory.Ldap.Connection.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using System;
using System.Threading;
using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Rfc2251;
using Novell.Directory.Ldap.Utilclass;
using Syscert = System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Net.Security;

namespace Novell.Directory.Ldap
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Authentication;
    using System.Threading.Tasks;

    /// <summary> The class that creates a connection to the Ldap server. After the
    /// connection is made, a thread is created that reads data from the
    /// connection.
    /// 
    /// The application's thread sends a request to the MessageAgent class, which
    /// creates a Message class.  The Message class calls the writeMessage method
    /// of this class to send the request to the server. The application thread
    /// will then query the MessageAgent class for a response.
    /// 
    /// The reader thread multiplexes response messages received from the
    /// server to the appropriate Message class. Each Message class
    /// has its own message queue.
    /// 
    /// Unsolicited messages are process separately, and if the application
    /// has registered a handler, a separate thread is created for that
    /// application's handler to process the message.
    /// 
    /// Note: the reader thread must not be a "selfish" thread, since some
    /// operating systems do not time slice.
    /// 
    /// </summary>
    /*package*/
    sealed class ConnectionV2 : IDisposable
    {
        public event CertificateValidationCallback OnCertificateValidation;
        public enum CertificateProblem : long
        {
            CertExpired = 0x800B0101,
            CertValidityperiodnesting = 0x800B0102,
            CertRole = 0x800B0103,
            CertPathlenconst = 0x800B0104,
            CertCritical = 0x800B0105,
            CertPurpose = 0x800B0106,
            CertIssuerchaining = 0x800B0107,
            CertMalformed = 0x800B0108,
            CertUntrustedroot = 0x800B0109,
            CertChaining = 0x800B010A,
            CertRevoked = 0x800B010C,
            CertUntrustedtestroot = 0x800B010D,
            CertRevocationFailure = 0x800B010E,
            CertCnNoMatch = 0x800B010F,
            CertWrongUsage = 0x800B0110,
            CertUntrustedca = 0x800B0112
        }

        private static string GetProblemMessage(CertificateProblem problem)
        {
            string problemMessage = "";
            string problemCodeName = CertificateProblem.GetName(typeof(CertificateProblem), problem);
            if (problemCodeName != null)
                problemMessage = problemMessage + problemCodeName;
            else
                problemMessage = "Unknown Certificate Problem";
            return problemMessage;
        }

        private readonly ArrayList _handshakeProblemsEncountered = new ArrayList();

        private void InitBlock()
        {
            _writeSemaphore = new object();
            _encoder = new LBEREncoder();
            _decoder = new LBERDecoder();
            _stopReaderMessageId = ContinueReading;
            _messages = new MessageVector<Message>(5, 5);
            _unsolicitedListeners = new List<LdapUnsolicitedNotificationListener>(3);
        }

        /// <summary>  Indicates whether clones exist for LdapConnection
        /// 
        /// </summary>
        /// <returns> true if clones exist, false otherwise.
        /// </returns>
        internal bool Cloned => (_cloneCount > 0);

        internal bool Ssl { get; set; } = false;

        /// <summary> gets the host used for this connection</summary>
        internal string Host { get; private set; } = null;

        /// <summary> gets the port used for this connection</summary>
        internal int Port { get; private set; } = 0;

        /// <summary> sets the writeSemaphore id used for active bind operation</summary>
        internal int BindSemId
        {
            /* package */

            get
            {
                return _bindSemaphoreId;
            }

            /* package */

            set
            {
                _bindSemaphoreId = value;

            }

        }
        /// <summary> checks if the writeSemaphore id used for active bind operation is clear</summary>
        internal bool BindSemIdClear
        {
            /* package */

            get
            {
                if (_bindSemaphoreId == 0)
                {
                    return true;
                }
                return false;
            }

        }
        /// <summary> Return whether the application is bound to this connection.
        /// Note: an anonymous bind returns false - not bound
        /// </summary>
        internal bool Bound
        {
            /* package */

            get
            {
                if (BindProperties != null)
                {
                    // Bound if not anonymous
                    return (!BindProperties.Anonymous);
                }
                return false;
            }

        }

        /// <summary> Return whether a connection has been made</summary>
        internal bool Connected => (_inRenamed != null);
        internal static System.String sdk;
        /* package */
        internal static System.Int32 protocol;
        /* package */
        internal static System.String security = "simple";
        /// <summary> 
        /// Sets the authentication credentials in the object
        /// and set flag indicating successful bind.
        /// 
        /// 
        /// 
        /// </summary>
        /// <returns>  The BindProperties object for this connection.
        /// </returns>
        /// <summary> 
        /// Sets the authentication credentials in the object
        /// and set flag indicating successful bind.
        /// 
        /// 
        /// 
        /// </summary>
        /// <param name="bindProps">  The BindProperties object to set.
        /// </param>
        internal BindProperties BindProperties { get; set; } = null;

        /// <summary> Gets the current referral active on this connection if created to
        /// follow referrals.
        /// 
        /// </summary>
        /// <returns> the active referral url
        /// </returns>
        /// <summary> Sets the current referral active on this connection if created to
        /// follow referrals.
        /// </summary>
        internal ReferralInfo ActiveReferral { get; set; } = null;

        /// <summary> Returns the name of this Connection, used for debug only
        /// 
        /// </summary>
        /// <returns> the name of this connection
        /// </returns>
        internal string ConnectionName { get; } = string.Empty;

        private object _writeSemaphore;
        private int _writeSemaphoreOwner = 0;
        private int _writeSemaphoreCount = 0;

        // We need a message number for disconnect to grab the semaphore,
        // but may not have one, so we invent a unique one.
        private int _ephemeralId = -1;

        private int _bindSemaphoreId = 0; // 0 is never used by to lock a semaphore

        private Thread _reader; // New thread that reads data from the server.

        private Task _readerTask; // New thread that reads data from the server.

        private Thread _deadReader; // Identity of last reader thread

        private IOException _deadReaderException; // Last exception of reader

        private LBEREncoder _encoder;

        private LBERDecoder _decoder;

        /*
		* socket is the current socket being used.
		* nonTLSBackup is the backup socket if startTLS is called.
		* if nonTLSBackup is null then startTLS has not been called,
		* or stopTLS has been called to end TLS protection
		*/
        private Socket _sock = null;
        private TcpClient _socket = null;
        private TcpClient _nonTlsBackup = null;

        private Stream _inRenamed = null;
        private Stream _outRenamed = null;
        // When set to true the client connection is up and running
        private bool _clientActive = true;

        // Indicates we have received a server shutdown unsolicited notification
        private bool _unsolSvrShutDnNotification = false;

        //  Ldap message IDs are all positive numbers so we can use negative
        //  numbers as flags.  This are flags assigned to stopReaderMessageID
        //  to tell the reader what state we are in.
        private const int ContinueReading = -99;
        private const int StopReading = -98;

        //  Stops the reader thread when a Message with the passed-in ID is read.
        //  This parameter is set by stopReaderOnReply and stopTLS
        private int _stopReaderMessageId;


        // Place to save message information classes
        private MessageVector<Message> _messages;

        // Connection created to follow referral

        // Place to save unsolicited message listeners
        private List<LdapUnsolicitedNotificationListener> _unsolicitedListeners;

        // The LdapSocketFactory to be used as the default to create new connections
        //		private static LdapSocketFactory socketFactory = null;
        // The LdapSocketFactory used for this connection
        //		private LdapSocketFactory mySocketFactory;
        // Number of clones in addition to original LdapConnection using this
        // connection.
        private int _cloneCount = 0;

        // These attributes can be retreived using the getProperty
        // method in LdapConnection.  Future releases might require
        // these to be local variables that can be modified using
        // the setProperty method.
        /* package */
        internal static string Sdk;
        /* package */
        internal static int Protocol;
        /* package */
        internal static string Security = "simple";

        /// <summary> Create a new Connection object
        /// 
        /// </summary>
        /// <param name="factory">specifies the factory to use to produce SSL sockets.
        /// </param>
        /* package */
        //		internal Connection(LdapSocketFactory factory)
        internal ConnectionV2()
        {
            InitBlock();
        }

        /// <summary> Copy this Connection object.
        /// 
        /// This is not a true clone, but creates a new object encapsulating
        /// part of the connection information from the original object.
        /// The new object will have the same default socket factory,
        /// designated socket factory, host, port, and protocol version
        /// as the original object.
        /// The new object is NOT be connected to the host.
        /// 
        /// </summary>
        /// <returns> a shallow copy of this object
        /// </returns>
        /* package */
        internal object Copy()
        {
            var connection = new ConnectionV2 { Host = Host, Port = Port };
            Connection.protocol = Protocol;
            return connection;
        }

        /// <summary> Acquire a simple counting semaphore that synchronizes state affecting
        /// bind. This method generates an ephemeral message id (negative number).
        /// 
        /// We bind using the message ID because a different thread may unlock
        /// the semaphore than the one that set it.  It is cleared when the
        /// response to the bind is processed, or when the bind operation times out.
        /// 
        /// Returns when the semaphore is acquired
        /// 
        /// </summary>
        /// <returns> the ephemeral message id that identifies semaphore's owner
        /// </returns>
        /* package */
        internal int acquireWriteSemaphore()
        {
            return acquireWriteSemaphore(0);
        }

        /// <summary> Acquire a simple counting semaphore that synchronizes state affecting
        /// bind. The semaphore is held by setting a value in writeSemaphoreOwner.
        /// 
        /// We bind using the message ID because a different thread may unlock
        /// the semaphore than the one that set it.  It is cleared when the
        /// response to the bind is processed, or when the bind operation times out.
        /// Returns when the semaphore is acquired.
        /// 
        /// </summary>
        /// <param name="msgId">a value that identifies the owner of this semaphore. A
        /// value of zero means assign a unique semaphore value.
        /// 
        /// </param>
        /// <returns> the semaphore value used to acquire the lock
        /// </returns>
        /* package */
        internal int acquireWriteSemaphore(int msgId)
        {
            int id = msgId;
            lock (_writeSemaphore)
            {
                if (id == 0)
                {
                    _ephemeralId = ((_ephemeralId == int.MinValue) ? (_ephemeralId = -1) : --_ephemeralId);
                    id = _ephemeralId;
                }
                while (true)
                {
                    if (_writeSemaphoreOwner == 0)
                    {
                        // we have acquired the semahpore
                        _writeSemaphoreOwner = id;
                        break;
                    }
                    else
                    {
                        if (_writeSemaphoreOwner == id)
                        {
                            // we already own the semahpore
                            break;
                        }
                        //try
                        //{
                        // Keep trying for the lock
                        System.Threading.Monitor.Wait(_writeSemaphore);
                        continue;
                        //}
                        //catch (ThreadInterruptedException ex)
                        //{
                        //	// Keep trying for the lock
                        //	continue;
                        //}
                    }
                }
                _writeSemaphoreCount++;
            }
            return id;
        }

        /// <summary> Release a simple counting semaphore that synchronizes state affecting
        /// bind.  Frees the semaphore when number of acquires and frees for this
        /// thread match.
        /// 
        /// </summary>
        /// <param name="msgId">a value that identifies the owner of this semaphore
        /// </param>
        /* package */
        internal void FreeWriteSemaphore(int msgId)
        {
            lock (_writeSemaphore)
            {
                if (_writeSemaphoreOwner == 0)
                {
                    throw new Exception("Connection.freeWriteSemaphore(" + msgId + "): semaphore not owned by any thread");
                }
                if (_writeSemaphoreOwner != msgId)
                {
                    throw new Exception("Connection.freeWriteSemaphore(" + msgId + "): thread does not own the semaphore, owned by " + _writeSemaphoreOwner);
                }
                // if all instances of this semaphore for this thread are released,
                // wake up all threads waiting.
                if (--_writeSemaphoreCount == 0)
                {
                    _writeSemaphoreOwner = 0;
                    Monitor.Pulse(_writeSemaphore);
                }
            }
        }

        /*
		* Wait until the reader thread ID matches the specified parameter.
		* Null = wait for the reader to terminate
		* Non Null = wait for the reader to start
		* Returns when the ID matches, i.e. reader stopped, or reader started.
		*
		* @param the thread id to match
		*/

        private void WaitForReader(Thread thread)
        {
            // wait for previous reader thread to terminate
            var rInst = _reader;
            var tInst = thread;

            while (!Equals(rInst, tInst))
            {
                // Don't initialize connection while previous reader thread still
                // active.
                /*
                * The reader thread may start and immediately terminate.
                * To prevent the waitForReader from waiting forever
                * for the dead to rise, we leave traces of the deceased.
                * If the thread is already gone, we throw an exception.
                */
                if (thread == _deadReader)
                {
                    if (thread == null)
                    {
                        return; /* then we wanted a shutdown */
                    }
                    var lex = _deadReaderException;
                    _deadReaderException = null;
                    _deadReader = null;
                    throw new LdapException(ExceptionMessages.CONNECTION_READER, LdapException.CONNECT_ERROR, null, lex);
                }
                lock (this)
                {
                    Monitor.Wait(this, TimeSpan.FromMilliseconds(5));
                }
                rInst = _reader;
                tInst = thread;
            }
            _deadReaderException = null;
            _deadReader = null;
        }

        internal void connect(string host, int port)
        {
            Connect(host, port, 0);
        }


        public bool ServerCertificateValidation(Syscert.X509Certificate certificate, int[] certificateErrors)
        {
            if (null != OnCertificateValidation)
            {
                return OnCertificateValidation(certificate, certificateErrors);
            }

            return DefaultCertificateValidationHandler(certificate, certificateErrors);
        }

        public bool DefaultCertificateValidationHandler(Syscert.X509Certificate certificate, int[] certificateErrors)
        {
            bool retFlag = false;

            if (certificateErrors != null &&
                certificateErrors.Length > 0)
            {
                if (certificateErrors.Length == 1 && certificateErrors[0] == -2146762481)
                {
                    retFlag = true;
                }
                else
                {
                    Console.WriteLine("Detected errors in the Server Certificate:");

                    for (int i = 0; i < certificateErrors.Length; i++)
                    {
                        _handshakeProblemsEncountered.Add((CertificateProblem)((uint)certificateErrors[i]));
                        Console.WriteLine(certificateErrors[i]);
                    }
                    retFlag = false;
                }
            }
            else
            {
                retFlag = true;
            }


            // Skip the server cert errors.
            return retFlag;
        }


        /***********************************************************************/
        /// <summary> Constructs a TCP/IP connection to a server specified in host and port.
        /// Starts the reader thread.
        /// 
        /// </summary>
        /// <param name="host">The host to connect to.
        /// 
        /// </param>
        /// <param name="port">The port on the host to connect to.
        /// 
        /// </param>
        /// <param name="semaphoreId">The write semaphore ID to use for the connect
        /// </param>
        private void Connect(string host, int port, int semaphoreId)
        {
            WaitForReader(null);
            _unsolSvrShutDnNotification = false;

            int semId = acquireWriteSemaphore(semaphoreId);
            try
            {
                // Make socket connection to specified host and port
                if (port == 0)
                {
                    port = 389; //LdapConnection.DEFAULT_PORT;
                }

                try
                {
                    if ((_inRenamed == null) || (_outRenamed == null))
                    {
                        if (Ssl)
                        {
                            Host = host;
                            Port = port;
                            _socket = new TcpClient();
                            _socket.ConnectAsync(host, port).Wait();
                            var sslStream = new SslStream(_socket.GetStream(), false, UserCertificateValidationCallback);
                            sslStream.AuthenticateAsClientAsync(host, new Syscert.X509Certificate2Collection(), SslProtocols.Tls12, false).Wait();
                            _inRenamed = sslStream;
                            _outRenamed = sslStream;
                        }
                        else
                        {
                            _socket = new TcpClient();
                            _socket.ConnectAsync(host, port).Wait();
                            _inRenamed = _socket.GetStream();
                            _outRenamed = _socket.GetStream();
                        }
                    }
                    else
                    {
                        Console.WriteLine("connect input/out Stream specified");

                    }
                }
                catch (SocketException se)
                {
                    // Unable to connect to server host:port
                    // freeWriteSemaphore(semId); 
                    _sock = null;
                    _socket = null;
                    throw new LdapException(ExceptionMessages.CONNECTION_ERROR, new object[] { host, port }, LdapException.CONNECT_ERROR, null, se);
                }

                catch (IOException ioe)
                {
                    // Unable to connect to server host:port
                    // freeWriteSemaphore(semId);
                    _sock = null;
                    _socket = null;
                    throw new LdapException(ExceptionMessages.CONNECTION_ERROR, new object[] { host, port }, LdapException.CONNECT_ERROR, null, ioe);
                }
                // Set host and port
                Host = host;
                Port = port;
                // start the reader thread
                StartReader();
                _clientActive = true; // Client is up
            }
            finally
            {
                FreeWriteSemaphore(semId);
            }
        }

        private bool UserCertificateValidationCallback(object sender, Syscert.X509Certificate certificate, Syscert.X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            //TODO : just a temp stuff
            return true;
        }

        /// <summary>  Increments the count of cloned connections</summary>
        /* package */
        internal void IncrCloneCount()
        {
            lock (this)
            {
                _cloneCount++;
            }
        }

        /// <summary> Destroys a clone of <code>LdapConnection</code>.
        /// 
        /// This method first determines if only one <code>LdapConnection</code>
        /// object is associated with this connection, i.e. if no clone exists.
        /// 
        /// If no clone exists, the socket is closed, and the current
        /// <code>Connection</code> object is returned.
        /// 
        /// If multiple <code>LdapConnection</code> objects are associated
        /// with this connection, i.e. clones exist, a {@link #copy} of the
        /// this object is made, but is not connected to any host. This
        /// disassociates that clone from the original connection.  The new
        /// <code>Connection</code> object is returned.
        /// 
        /// Only one destroyClone instance is allowed to run at any one time.
        /// 
        /// If the connection is closed, any threads waiting for operations
        /// on that connection will wake with an LdapException indicating
        /// the connection is closed.
        /// 
        /// </summary>
        /// <param name="apiCall"><code>true</code> indicates the application is closing the
        /// connection or or creating a new one by calling either the
        /// <code>connect</code> or <code>disconnect</code> methods
        /// of <code>LdapConnection</code>.  <code>false</code>
        /// indicates that <code>LdapConnection</code> is being finalized.
        /// 
        /// </param>
        /// <returns> a Connection object or null if finalizing.
        /// </returns>
        /* package */
        internal ConnectionV2 DestroyClone(bool apiCall)
        {
            lock (this)
            {
                ConnectionV2 conn = this;

                if (_cloneCount > 0)
                {
                    _cloneCount--;
                    // This is a clone, set a new connection object.
                    if (apiCall)
                    {
                        conn = (ConnectionV2)this.Copy();
                    }
                    else
                    {
                        conn = null;
                    }
                }
                else
                {
                    if (_inRenamed != null)
                    {
                        // Not a clone and connected
                        /*
						* Either the application has called disconnect or connect
						* resulting in the current connection being closed. If the
						* application has any queues waiting on messages, we
						* need wake these up so the application does not hang.
						* The boolean flag indicates whether the close came
						* from an API call or from the object being finalized.
						*/
                        InterThreadException notify = new InterThreadException((apiCall ? ExceptionMessages.CONNECTION_CLOSED : ExceptionMessages.CONNECTION_FINALIZED), null, LdapException.CONNECT_ERROR, null, null);
                        // Destroy old connection
                        Dispose(false, "destroy clone", 0, notify);
                    }
                }
                return conn;
            }
        }

        /// <summary> clears the writeSemaphore id used for active bind operation</summary>
        /* package */
        internal void ClearBindSemId()
        {
            _bindSemaphoreId = 0;
            return;
        }

        /// <summary> Writes an LdapMessage to the Ldap server over a socket.
        /// 
        /// </summary>
        /// <param name="info">the Message containing the message to write.
        /// </param>
        /* package */
        internal void writeMessage(Message info)
        {
            var em = new ExceptionMessages();
            var contents = em.getContents();
            _messages.Add(info);

            // For bind requests, if not connected, attempt to reconnect
            if (info.BindRequest && (Connected == false) && ((object)Host != null))
            {
                Connect(Host, Port, info.MessageID);
            }
            if (Connected)
            {
                var msg = info.Request;
                writeMessage(msg);
            }
            var errorcount = 0;
            for (errorcount = 0; errorcount < contents.Length; errorcount++)
            {
                if ((string)contents[errorcount][0] == "CONNECTION_CLOSED")
                {
                    break;
                }
            }
            throw new LdapException(ExceptionMessages.CONNECTION_CLOSED, new object[] { Host, Port }, LdapException.CONNECT_ERROR, (string)contents[errorcount][1]);
        }
        internal void ProcessMessage(Message info)
        {
            var em = new ExceptionMessages();
            var contents = em.getContents();
            _messages.Add(info);

            // For bind requests, if not connected, attempt to reconnect
            if (info.BindRequest && (Connected == false) && (Host != null))
            {
                Connect(Host, Port, info.MessageID);
            }
            if (Connected)
            {
                var msg = info.Request;
                writeMessage(msg);
            }
            var errorcount = 0;
            for (errorcount = 0; errorcount < contents.Length; errorcount++)
            {
                if ((string)contents[errorcount][0] == "CONNECTION_CLOSED")
                {
                    break;
                }
            }
            throw new LdapException(ExceptionMessages.CONNECTION_CLOSED, new object[] { Host, Port }, LdapException.CONNECT_ERROR, (string)contents[errorcount][1]);
        }
        internal Task<LdapMessage> ProcessMessage(LdapMessage msg)
        {
            var tcs = new TaskCompletionSource<LdapMessage>();
            var myOut = _outRenamed;
            try
            {
                if (myOut == null)
                {
                    throw new IOException("Output stream not initialized");
                }
                if (!myOut.CanWrite)
                {
                    throw new IOException("Can't write to output stream");
                }
                var ber = msg.Asn1Object.getEncoding(_encoder);
                myOut.Write(SupportClass.ToByteArray(ber), 0, ber.Length);
                myOut.Flush();
                Task.Run(() => WaitForReply(tcs));
               
            }
            catch (IOException ioe)
            {
                if ((msg.Type == LdapMessage.BIND_REQUEST) && (Ssl))
                {
                    var strMsg = "Following problem(s) occurred while establishing SSL based Connection : ";
                    if (_handshakeProblemsEncountered.Count > 0)
                    {
                        strMsg += GetProblemMessage((CertificateProblem)_handshakeProblemsEncountered[0]);
                        for (var nProbIndex = 1; nProbIndex < _handshakeProblemsEncountered.Count; nProbIndex++)
                        {
                            strMsg += ", " + GetProblemMessage((CertificateProblem)_handshakeProblemsEncountered[nProbIndex]);
                        }
                    }
                    else
                    {
                        strMsg += "Unknown Certificate Problem";
                    }
                    throw new LdapException(strMsg, new object[] { Host, Port }, LdapException.SSL_HANDSHAKE_FAILED, null, ioe);
                }
                if (_clientActive)
                {
                    // We beliefe the connection was alive
                    if (_unsolSvrShutDnNotification)
                    {
                        // got server shutdown
                        throw new LdapException(ExceptionMessages.SERVER_SHUTDOWN_REQ, new object[] { Host, Port }, LdapException.CONNECT_ERROR, null, ioe);
                    }

                    // Other I/O Exceptions on host:port are reported as is
                    throw new LdapException(ExceptionMessages.IO_EXCEPTION, new object[] { Host, Port }, LdapException.CONNECT_ERROR, null, ioe);
                }
            }
            finally
            {
                _handshakeProblemsEncountered.Clear();
            }
            return tcs.Task;
        }

        public void WaitForReply(TaskCompletionSource<LdapMessage> completionSource)
        {
            var reason = "reader: thread stopping";
            InterThreadException notify = null;
            Message info = null;
            IOException ioex = null;
            bool isSet = false;
            try
            {
                while (!isSet)
                {
                    var myIn = _inRenamed;
                    if (myIn == null)
                    {
                        break;
                    }
                    var asn1Id = new Asn1Identifier(myIn);
                    if (asn1Id.Tag != Asn1Sequence.TAG)
                    {
                        continue;
                    }

                    // Turn the message into an RfcMessage class
                    var asn1Len = new Asn1Length(myIn);
                    var msg = new RfcLdapMessage(_decoder, myIn, asn1Len.Length);

                    var msgId = msg.MessageID;

                    try
                    {
                        //info = _messages.FindMessageById(msgId);
                        //info.putReply(msg); // queue & wake up waiting thread
                        var response = getResponse(msg);
                        isSet = true;
                        completionSource.SetResult(response);

                    }
                    catch (FieldAccessException)
                    {
                        if (msgId == 0)
                        {
                            NotifyAllUnsolicitedListeners(msg);
                            if (_unsolSvrShutDnNotification)
                            {
                                notify = new InterThreadException(ExceptionMessages.SERVER_SHUTDOWN_REQ, new object[] { Host, Port },
                                    LdapException.CONNECT_ERROR,
                                    null,
                                    null);

                                return;
                            }

                        }
                    }
                    if ((_stopReaderMessageId == msgId) || (_stopReaderMessageId == StopReading))
                    {
                        // Stop the reader Thread.
                        return;
                    }
                }
            }
            catch (IOException ioe)
            {
                ioex = ioe;
                if ((_stopReaderMessageId != StopReading) && _clientActive)
                {
                    notify = new InterThreadException(ExceptionMessages.CONNECTION_WAIT, new object[] { Host, Port }, LdapException.CONNECT_ERROR, ioe, info);
                }
                // The connection is no good, don't use it any more
                _inRenamed = null;
                _outRenamed = null;
            }
            finally
            {
                completionSource.SetException(notify);
                if ((!this._clientActive) || (notify != null))
                {
                    this.Dispose(false, reason, 0, notify);
                }
                else
                {
                    this._stopReaderMessageId = ContinueReading;
                }
            }
            this._deadReaderException = ioex;
            this._deadReader = this._reader;
            this._reader = null;
        }


        private LdapMessage getResponse(RfcLdapMessage message)
        {
            LdapMessage response;
            switch (message.Type)
            {

                case LdapMessage.SEARCH_RESPONSE:
                    response = new LdapSearchResult(message);
                    break;

                case LdapMessage.SEARCH_RESULT_REFERENCE:
                    response = new LdapSearchResultReference(message);
                    break;

                case LdapMessage.EXTENDED_RESPONSE:
                    ExtResponseFactory fac = new ExtResponseFactory();
                    response = ExtResponseFactory.convertToExtendedResponse(message);
                    break;

                case LdapMessage.INTERMEDIATE_RESPONSE:
                    response = IntermediateResponseFactory.convertToIntermediateResponse(message);
                    break;

                default:
                    response = new LdapResponse(message);
                    break;

            }
            return response;
        }


        internal void writeMessage(LdapMessage msg)
        {
            // Get the correct semaphore id for bind operations
            var semaphoreId = _bindSemaphoreId == 0 ? msg.MessageID : _bindSemaphoreId;
            var myOut = _outRenamed;

            acquireWriteSemaphore(semaphoreId);
            try
            {
                if (myOut == null)
                {
                    throw new IOException("Output stream not initialized");
                }
                if (!myOut.CanWrite)
                {
                    return;
                }
                var ber = msg.Asn1Object.getEncoding(_encoder);
                myOut.Write(SupportClass.ToByteArray(ber), 0, ber.Length);
                myOut.Flush();
            }
            catch (IOException ioe)
            {
                if ((msg.Type == LdapMessage.BIND_REQUEST) && (Ssl))
                {
                    var strMsg = "Following problem(s) occurred while establishing SSL based Connection : ";
                    if (_handshakeProblemsEncountered.Count > 0)
                    {
                        strMsg += GetProblemMessage((CertificateProblem)_handshakeProblemsEncountered[0]);
                        for (var nProbIndex = 1; nProbIndex < _handshakeProblemsEncountered.Count; nProbIndex++)
                        {
                            strMsg += ", " + GetProblemMessage((CertificateProblem)_handshakeProblemsEncountered[nProbIndex]);
                        }
                    }
                    else
                    {
                        strMsg += "Unknown Certificate Problem";
                    }
                    throw new LdapException(strMsg, new object[] { Host, Port }, LdapException.SSL_HANDSHAKE_FAILED, null, ioe);
                }
                /*
				* IOException could be due to a server shutdown notification which
				* caused our Connection to quit.  If so we send back a slightly
				* different error message.  We could have checked this a little
				* earlier in the method but that would be an expensive check each
				* time we send out a message.  Since this shutdown request is
				* going to be an infrequent occurence we check for it only when
				* we get an IOException.  shutdown() will do the cleanup.
				*/
                if (_clientActive)
                {
                    // We beliefe the connection was alive
                    if (_unsolSvrShutDnNotification)
                    {
                        // got server shutdown
                        throw new LdapException(ExceptionMessages.SERVER_SHUTDOWN_REQ, new object[] { Host, Port }, LdapException.CONNECT_ERROR, null, ioe);
                    }

                    // Other I/O Exceptions on host:port are reported as is
                    throw new LdapException(ExceptionMessages.IO_EXCEPTION, new object[] { Host, Port }, LdapException.CONNECT_ERROR, null, ioe);
                }
            }
            finally
            {
                FreeWriteSemaphore(semaphoreId);
                _handshakeProblemsEncountered.Clear();
            }
        }

        /// <summary> Returns the message agent for this msg ID</summary>
        /* package */
        internal MessageAgent GetMessageAgent(int msgId)
        {
            Message info = _messages.FindMessageById(msgId);
            return info.MessageAgent;
        }

        /// <summary> Removes a Message class from the Connection's list
        /// 
        /// </summary>
        /// <param name="info">the Message class to remove from the list
        /// </param>
        /* package */
        internal void RemoveMessage(Message info)
        {
            if (_messages.Contains(info))
            {
                _messages.Remove(info);
            }
        }

        /// <summary> Cleans up resources associated with this connection.</summary>
        ~ConnectionV2()
        {
            Dispose(false, "Finalize", 0, null);
        }

        //Adding code here earlier code
        public void Dispose()
        {
            Dispose(true, "Finalize", 0, null);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing, string reason, int semaphoreId, InterThreadException notifyUser)
        {
            if (!disposing)
            {
                if (!_clientActive)
                {
                    return;
                }
                _clientActive = false;
                while (true)
                {
                    // remove messages from connection list and send abandon
                    Message info;
                    try
                    {
                        var tempObject = _messages[0];
                        _messages.RemoveAt(0);
                        info = tempObject;
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        // No more messages
                        break;
                    }
                    info.Abandon(null, notifyUser); // also notifies the application
                }

                int semId = acquireWriteSemaphore(semaphoreId);
                // Now send unbind if socket not closed
                if ((BindProperties != null) && (_outRenamed != null) && (_outRenamed.CanWrite) && (!BindProperties.Anonymous))
                {
                    try
                    {
                        LdapMessage msg = new LdapUnbindRequest(null);
                        sbyte[] ber = msg.Asn1Object.getEncoding(_encoder);
                        _outRenamed.Write(SupportClass.ToByteArray(ber), 0, ber.Length);
                        _outRenamed.Flush();
                        _outRenamed.Dispose();
                    }
                    catch (System.Exception ex)
                    {
                        ; // don't worry about error
                    }
                }
                BindProperties = null;
                if (_socket != null || _sock != null)
                {
                    // Just before closing the sockets, abort the reader thread
                    if ((_reader != null) && (reason != "reader: thread stopping"))
                    {
                        //reader.Abort();
                    }
                    // Close the socket
                    try
                    {
                        _inRenamed?.Dispose();

                        if (Ssl)
                        {
                            _outRenamed?.Dispose();
                        }
                        _sock?.Dispose();
                        _socket?.Dispose();
                    }
                    catch (IOException)
                    {
                        // ignore problem closing socket
                    }
                    _socket = null;
                    _sock = null;
                    _inRenamed = null;
                    _outRenamed = null;

                }
                FreeWriteSemaphore(semId);
            }
        }

        /// <summary> This tests to see if there are any outstanding messages.  If no messages
        /// are in the queue it returns true.  Each message will be tested to
        /// verify that it is complete.
        /// <I>The writeSemaphore must be set for this method to be reliable!</I>
        /// 
        /// </summary>
        /// <returns> true if no outstanding messages
        /// </returns>
        /* package */
        internal bool AreMessagesComplete()
        {
            var messages = _messages.ObjectArray;

            // Check if SASL bind in progress
            if (_bindSemaphoreId != 0)
            {
                return false;
            }

            // Check if any messages queued
            return messages.Length == 0 || messages.All(message => message.Complete);
        }

        /// <summary> The reader thread will stop when a reply is read with an ID equal
        /// to the messageID passed in to this method.  This is used by
        /// LdapConnection.StartTLS.
        /// </summary>
        /* package */
        internal void StopReaderOnReply(int messageId)
        {
            _stopReaderMessageId = messageId;
        }

        /// <summary>startReader
        /// startReader should be called when socket and io streams have been
        /// set or changed.  In particular after client.Connection.startTLS()
        /// It assumes the reader thread is not running.
        /// </summary>
        /* package */
        internal void StartReader()
        {
            // Start Reader Thread
            var r = new Thread(new ReaderThread(this).Run) { IsBackground = true };
            // If the last thread running, allow exit.
            //r.Start();
           // WaitForReader(r);
        }

        /// <summary> Indicates if the conenction is using TLS protection
        ///
        /// Return true if using TLS protection
        /// </summary>
        internal bool Tls => (this._nonTlsBackup != null);

        /// <summary> StartsTLS, in this package, assumes the caller has:
        /// 1) Acquired the writeSemaphore
        /// 2) Stopped the reader thread
        /// 3) checked that no messages are outstanding on this connection.
        /// 
        /// After calling this method upper layers should start the reader
        /// by calling startReader()
        /// 
        /// In the client.Connection, StartTLS assumes Ldap.LdapConnection will
        /// stop and start the reader thread.  Connection.StopTLS will stop
        /// and start the reader thread.
        /// </summary>
        /* package */
        internal void StartTls()
        {
            try
            {
                WaitForReader(null);
                _nonTlsBackup = _socket;
                var sslStream = new SslStream(_socket.GetStream(), true, UserCertificateValidationCallback);
                sslStream.AuthenticateAsClientAsync(Host, new Syscert.X509Certificate2Collection(), SslProtocols.Tls12, false).Wait();
                _inRenamed = sslStream;
                _outRenamed = sslStream;
            }
            catch (IOException ioe)
            {
                _nonTlsBackup = null;
                throw new LdapException("Could not negotiate a secure connection", LdapException.CONNECT_ERROR, null, ioe);
            }
            catch (Exception uhe)
            {
                _nonTlsBackup = null;
                throw new LdapException("The host is unknown", LdapException.CONNECT_ERROR, null, uhe);
            }
        }

        /*
		* Stops TLS.
		*
		* StopTLS, in this package, assumes the caller has:
		*  1) blocked writing (acquireWriteSemaphore).
		*  2) checked that no messages are outstanding.
		*
		*  StopTLS Needs to do the following:
		*  1) close the current socket
		*      - This stops the reader thread
		*      - set STOP_READING flag on stopReaderMessageID so that
		*        the reader knows that the IOException is planned.
		*  2) replace the current socket with nonTLSBackup,
		*  3) and set nonTLSBackup to null;
		*  4) reset input and outputstreams
		*  5) start the reader thread by calling startReader
		*
		*  Note: Sun's JSSE doesn't allow the nonTLSBackup socket to be
		* used any more, even though autoclose was false: you get an IOException.
		* IBM's JSSE hangs when you close the JSSE socket.
		*/
        /* package */

        internal void StopTls()
        {
            try
            {
                _stopReaderMessageId = StopReading;
                _outRenamed.Dispose();
                _inRenamed.Dispose();
                WaitForReader(null);
                _socket = _nonTlsBackup;
                _inRenamed = _socket.GetStream();
                _outRenamed = _socket.GetStream();
                // Allow the new reader to start
                _stopReaderMessageId = ContinueReading;
            }
            catch (IOException ioe)
            {
                throw new LdapException(ExceptionMessages.STOPTLS_ERROR, LdapException.CONNECT_ERROR, null, ioe);
            }
            finally
            {
                _nonTlsBackup = null;
                StartReader();
            }
        }
        ///TLS not supported in first release		

        public class ReaderThread
        {
            private void InitBlock(ConnectionV2 enclosingInstance)
            {
                this.EnclosingInstance = enclosingInstance;
            }

            public ConnectionV2 EnclosingInstance { get; private set; }

            public ReaderThread(ConnectionV2 enclosingInstance)
            {
                InitBlock(enclosingInstance);
                return;
            }

            /// <summary> This thread decodes and processes RfcLdapMessage's from the server.
            /// 
            /// Note: This thread needs a graceful shutdown implementation.
            /// </summary>
            public virtual void Run()
            {
                var reason = "reader: thread stopping";
                InterThreadException notify = null;
                Message info = null;
                IOException ioex = null;
                EnclosingInstance._reader = Thread.CurrentThread;
                try
                {
                    for (;;)
                    {
                        // -------------------------------------------------------
                        // Decode an RfcLdapMessage directly from the socket.
                        // -------------------------------------------------------
                        /* get current value of in, keep value consistant
						* though the loop, i.e. even during shutdown
						*/
                        var myIn = EnclosingInstance._inRenamed;
                        if (myIn == null)
                        {
                            break;
                        }
                        var asn1Id = new Asn1Identifier(myIn);
                        if (asn1Id.Tag != Asn1Sequence.TAG)
                        {
                            continue; // loop looking for an RfcLdapMessage identifier
                        }

                        // Turn the message into an RfcMessage class
                        var asn1Len = new Asn1Length(myIn);
                        var msg = new RfcLdapMessage(EnclosingInstance._decoder, myIn, asn1Len.Length);

                        // ------------------------------------------------------------
                        // Process the decoded RfcLdapMessage.
                        // ------------------------------------------------------------
                        var msgId = msg.MessageID;

                        // Find the message which requested this response.
                        // It is possible to receive a response for a request which
                        // has been abandoned. If abandoned, throw it away
                        try
                        {
                            info = EnclosingInstance._messages.FindMessageById(msgId);
                            info.putReply(msg); // queue & wake up waiting thread
                        }
                        catch (FieldAccessException ex)
                        {
                            /*
							* We get the NoSuchFieldException when we could not find
							* a matching message id.  First check to see if this is
							* an unsolicited notification (msgID == 0). If it is not
							* we throw it away. If it is we call any unsolicited
							* listeners that might have been registered to listen for these
							* messages.
							*/

                            /* Note the location of this code.  We could have required
							* that message ID 0 be just like other message ID's but
							* since message ID 0 has to be treated specially we have
							* a separate check for message ID 0.  Also note that
							* this test is after the regular message list has been
							* checked for.  We could have always checked the list
							* of messages after checking if this is an unsolicited
							* notification but that would have inefficient as
							* message ID 0 is a rare event (as of this time).
							*/
                            if (msgId == 0)
                            {
                                // Notify any listeners that might have been registered
                                EnclosingInstance.NotifyAllUnsolicitedListeners(msg);
                                /*
								* Was this a server shutdown unsolicited notification.
								* IF so we quit. Actually calling the return will
								* first transfer control to the finally clause which
								* will do the necessary clean up.
								*/
                                if (EnclosingInstance._unsolSvrShutDnNotification)
                                {
                                    notify = new InterThreadException(
                                        ExceptionMessages.SERVER_SHUTDOWN_REQ,
                                        new object[] { EnclosingInstance.Host, EnclosingInstance.Port },
                                        LdapException.CONNECT_ERROR,
                                        null,
                                        null);

                                    return;
                                }
                            }
                        }
                        if ((EnclosingInstance._stopReaderMessageId == msgId) || (EnclosingInstance._stopReaderMessageId == StopReading))
                        {
                            // Stop the reader Thread.
                            return;
                        }
                    }
                }
                //catch(ThreadAbortException tae)
                //{
                //	// Abort has been called on reader
                //	// before closing sockets, from shutdown
                //	return;
                //}

                catch (IOException ioe)
                {
                    ioex = ioe;
                    if ((EnclosingInstance._stopReaderMessageId != StopReading) && EnclosingInstance._clientActive)
                    {
                        // Connection lost waiting for results from host:port
                        notify = new InterThreadException(
                            ExceptionMessages.CONNECTION_WAIT,
                            new object[] { EnclosingInstance.Host, EnclosingInstance.Port },
                            LdapException.CONNECT_ERROR,
                            ioe,
                            info);
                    }
                    // The connection is no good, don't use it any more
                    EnclosingInstance._inRenamed = null;
                    EnclosingInstance._outRenamed = null;
                }
                finally
                {
                    /*
					* There can be four states that the reader can be in at this point:
					*  1) We are starting TLS and will be restarting the reader
					*     after we have negotiated TLS.
					*      - Indicated by whether stopReaderMessageID does not
					*        equal CONTINUE_READING.
					*      - Don't call Shutdown.
					*  2) We are stoping TLS and will be restarting after TLS is
					*     stopped.
					*      - Indicated by an IOException AND stopReaderMessageID equals
					*        STOP_READING - in which case notify will be null.
					*      - Don't call Shutdown
					*  3) We receive a Server Shutdown notification.
					*      - Indicated by messageID equal to 0.
					*      - call Shutdown.
					*  4) Another error occured
					*      - Indicated by an IOException AND notify is not NULL
					*      - call Shutdown.
					*/
                    if ((!this.EnclosingInstance._clientActive) || (notify != null))
                    {
                        //#3 & 4
                        this.EnclosingInstance.Dispose(false, reason, 0, notify);
                    }
                    else
                    {
                        this.EnclosingInstance._stopReaderMessageId = Novell.Directory.Ldap.ConnectionV2.ContinueReading;
                    }
                }
                this.EnclosingInstance._deadReaderException = ioex;
                this.EnclosingInstance._deadReader = this.EnclosingInstance._reader;
                this.EnclosingInstance._reader = null;
                return;
            }
        } // End class ReaderThread

        /// <summary>Add the specific object to the list of listeners that want to be
        /// notified when an unsolicited notification is received.
        /// </summary>
        /* package */
        internal void AddUnsolicitedNotificationListener(LdapUnsolicitedNotificationListener listener)
        {
            _unsolicitedListeners.Add(listener);
        }

        /// <summary>Remove the specific object from current list of listeners</summary>
        /* package */
        internal void RemoveUnsolicitedNotificationListener(LdapUnsolicitedNotificationListener listener)
        {
            if (_unsolicitedListeners.Contains(listener))
            {
                _unsolicitedListeners.Remove(listener);
            }
        }

        /// <summary>Inner class defined so that we can spawn off each unsolicited
        /// listener as a seperate thread.  We did not want to call the
        /// unsolicited listener method directly as this would have tied up our
        /// deamon listener thread in the applications unsolicited listener method.
        /// Since we do not know what the application unsolicited listener
        /// might be doing and how long it will take to process the uncoslicited
        /// notification.  We use this class to spawn off the unsolicited
        /// notification as a separate thread
        /// </summary>
        private class UnsolicitedListenerThread : SupportClass.ThreadClass
        {
            private void InitBlock(ConnectionV2 enclosingInstance)
            {
                this._enclosingInstance = enclosingInstance;
            }
            private ConnectionV2 _enclosingInstance;
            public ConnectionV2 EnclosingInstance
            {
                get
                {
                    return _enclosingInstance;
                }

            }
            private LdapUnsolicitedNotificationListener _listenerObj;
            private LdapExtendedResponse _unsolicitedMsg;

            /* package */
            internal UnsolicitedListenerThread(ConnectionV2 enclosingInstance, LdapUnsolicitedNotificationListener l, LdapExtendedResponse m)
            {
                InitBlock(enclosingInstance);
                this._listenerObj = l;
                this._unsolicitedMsg = m;
                return;
            }

            public override void Run()
            {
                _listenerObj.messageReceived(_unsolicitedMsg);
                return;
            }
        }

        private void NotifyAllUnsolicitedListeners(RfcLdapMessage message)
        {


            // MISSING:  If this is a shutdown notification from the server
            // set a flag in the Connection class so that we can throw an
            // appropriate LdapException to the application
            LdapMessage extendedLdapMessage = new LdapExtendedResponse(message);
            string notificationOid = ((LdapExtendedResponse)extendedLdapMessage).ID;
            if (notificationOid.Equals(LdapConnection.SERVER_SHUTDOWN_OID))
            {


                _unsolSvrShutDnNotification = true;
            }

            int numOfListeners = _unsolicitedListeners.Count;

            // Cycle through all the listeners
            for (int i = 0; i < numOfListeners; i++)
            {

                // Get next listener
                LdapUnsolicitedNotificationListener listener = (LdapUnsolicitedNotificationListener)_unsolicitedListeners[i];


                // Create a new ExtendedResponse each time as we do not want each listener
                // to have its own copy of the message
                LdapExtendedResponse tempLdapMessage = new LdapExtendedResponse(message);

                // Spawn a new thread for each listener to go process the message
                // The reason we create a new thread rather than just call the
                // the messageReceived method directly is beacuse we do not know
                // what kind of processing the notification listener class will
                // do.  We do not want our deamon thread to block waiting for
                // the notification listener method to return.
                UnsolicitedListenerThread u = new UnsolicitedListenerThread(this, listener, tempLdapMessage);
                u.Start();
            }


            return;
        }
        static ConnectionV2()
        {
            Sdk = new System.Text.StringBuilder("2.2.1").ToString();
            Protocol = 3;
        }
    }
}
