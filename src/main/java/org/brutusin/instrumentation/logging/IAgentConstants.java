package org.brutusin.instrumentation.logging;

public interface IAgentConstants {

	String TRACE_REGEX = "((?!org\\.apache\\.jsp.*))((^javax.*)|(^java\\.lang.*)|(^java\\.io.*)|(^org\\.apache.*)|(^java\\.nio.*)|(^java\\.util.*)|(^java\\.net.*)|(^sun.*)|(^java\\.security.*)|(^org\\.brutusin.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^org\\.hibernate.*)|(^java\\.sql.*)|(^com\\.mongodb.*)|(^org\\.apache\\.commons.*)|(^org\\.mongodb.*)|(^com\\.sun\\.org\\.apache.*)|(^com\\.sun\\.naming.*)|(^org\\.eclipse\\.jetty.*)|(^net\\.sourceforge\\.eclipsejetty.*)|(^java\\.awt.*)|(org\\.springframework.*)|(org\\.slf4j.*)|(com\\.sun\\.jmx.*)|(org\\.eclipse\\.jdt.*)|(com\\.opensymphony\\.xwork2.*)|(org\\.objectweb\\.asm.*)|(freemarker\\.cache.*)|(com\\.mchange\\.v2.*))";

	String SYSYTEM_CALL_START = "static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException";

	String[][] SKIP_LIST = { { "sun.usagetracker.UsageTrackerClient", "run" },
			{ "java.lang.ClassLoader", "loadClass", "loadLibrary", "getResourceAsStream" },
			{ "java.io.DeleteOnExitHook", "runHooks" }, { "java.util.jar.JarFile", "<init>" },
			{ "java.util.logging.LogManager", "readConfiguration" },
			{ "org.apache.catalina.startup.Bootstrap", "<clinit>" },
			{ "org.apache.catalina.startup.ClassLoaderFactory", "createClassLoader", "validateFile" },
			{ "com.sun.org.apache.xerces.internal.utils.SecuritySupport", "readJAXPProperty" },
			{ "org.apache.catalina.startup.CatalinaProperties", "loadProperties" },
			{ "org.apache.catalina.startup.Catalina", "stopServer", "configFile", "initDirs" },
			{ "javax.xml.parsers.FactoryFinder", "find" }, { "org.apache.tomcat.util.modeler.Registry", "load" },
			{ "org.apache.catalina.startup.ContextConfig", "<clinit>" }, { "org.apache.tomcat.jni.Library", "<init>" },
			{ "org.apache.catalina.util.ServerInfo", "<clinit>" },
			{ "org.apache.catalina.util.ExtensionValidator", "addFolderList", "<clinit>" },
			{ "org.apache.catalina.core.StandardContext", "postWorkDirectory" },
			{ "org.apache.catalina.util.CharsetMapper", "<init>" },
			{ "org.apache.catalina.webresources.AbstractFileResourceSet", "initInternal" },
			{ "org.apache.catalina.webresources.StandardRoot", "createMainResourceSet" },
			{ "org.apache.catalina.startup.ContextConfig", "fixDocBase", "processContextConfig", "contextConfig" },
			{ "org.apache.catalina.core.StandardHost", "getConfigBaseFile", "getAppBaseFile" },
			{ "org.apache.tomcat.util.file.ConfigFileLoader", "getInputStream", "<clinit>" },
			{ "com.sun.naming.internal.VersionHelper12$4", "run" },
			{ "org.apache.catalina.startup.WebappServiceLoader", "parseConfigFile" },
			{ "org.apache.catalina.loader.WebappClassLoaderBase", "getResourceAsStream" },
			{ "org.apache.tomcat.util.buf.B2CConverter", "<clinit>" },
			{ "org.apache.catalina.startup.ContextConfig", "getDefaultWebXmlFragment", "getWebXmlSource", "<clinit>",
					"fixDocBase", "contextConfig", "processContextConfig" },
			{ "org.apache.catalina.authenticator.jaspic.AuthConfigFactoryImpl", "<clinit>" },
			{ "java.net.URL", "openConnection" } };

	String[] FILE_OPEN_EXECUTORS = { "public java.io.File(java.lang.String,java.lang.String)",
			"public java.io.File(java.lang.String)" };

	String[] EXECUTORS = { SYSYTEM_CALL_START,

			// asynchronous mongo calls
			"public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",

			// synchronous mongo calls
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.LegacyProtocol<T>)",
			"private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
			"private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.LegacyProtocol<T>)",
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.Protocol<T>)",

			// mssql calls
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException,java.sql.SQLTimeoutException",
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException",

			// mysql calls
			"final com.mysql.jdbc.ResultSet com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.Statement,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,com.mysql.jdbc.Connection,int,int,boolean,java.lang.String,boolean) throws java.lang.Exception", // Mysql
																																																																		// Connector/J
																																																																		// 5.0.5
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception", // Mysql
																																																																				// Connector/J
																																																																				// 5.1.x
			"public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,boolean,java.lang.String,com.mysql.cj.api.mysqla.result.ColumnDefinition,com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction,com.mysql.cj.api.mysqla.io.ProtocolEntityFactory<T>) throws java.io.IOException", // Mysql
																																																																																																									// Connector/J
																																																																																																									// 6.x
			"public <T> T com.mysql.cj.NativeSession.execSQL(com.mysql.cj.Query,java.lang.String,int,com.mysql.cj.protocol.a.NativePacketPayload,boolean,com.mysql.cj.protocol.ProtocolEntityFactory<T, com.mysql.cj.protocol.a.NativePacketPayload>,java.lang.String,com.mysql.cj.protocol.ColumnDefinition,boolean)", // Mysql
																																																																														// Connector/J
																																																																														// 8.x

			// // FileWriter
			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)",

			// dynamic class loading
			"public java.net.URLClassLoader(java.net.URL[])",
			"private java.lang.Class<?> java.net.URLClassLoader.defineClass(java.lang.String,sun.misc.Resource) throws java.io.IOException",
			"public static java.net.URLClassLoader java.net.URLClassLoader.newInstance(java.net.URL[])",

			// File Input
//			"public java.io.FileInputStream(java.lang.String) throws java.io.FileNotFoundException",
//			"public java.io.FileInputStream(java.io.File) throws java.io.FileNotFoundException",
			
			};

	String MSSQL_EXECUTOR = "boolean com.microsoft.sqlserver.jdbc.SQLServerConnection.executeCommand(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String[] CONSTRUCTOR = { "<init>" };

	String[] ALL_CLASSES = { "com/mysql/jdbc/MysqlIO", "java/lang/ProcessImpl",
			// FileWriter
			"java/nio/file/spi/FileSystemProvider", "java/io/File", "com/microsoft/sqlserver/jdbc/SQLServerStatement",
			"com/mysql/cj/mysqla/io/MysqlaProtocol", "com/mysql/cj/NativeSession",
			"com/mongodb/connection/DefaultServerConnection", "com/mongodb/internal/connection/DefaultServerConnection",
			"com/mongodb/async/client/MongoClientImpl$2", "com/mongodb/async/client/AsyncOperationExecutorImpl",
			"com/mongodb/async/client/OperationExecutorImpl", "java/net/URLClassLoader"};

	String[][] ALL_METHODS = { { "sqlQueryDirect" }, { "start" }, { "newOutputStream" }, CONSTRUCTOR,
			{ "executeStatement" }, { "sqlQueryDirect" }, { "execSQL" }, { "executeProtocol" }, { "executeProtocol" },
			{ "execute" }, { "execute" }, { "execute" }, { "<init>", "newInstance" } };

	/** DB NAMES */
	String MSSQL_IDENTIFIER = "com.microsoft.sqlserver";
	String MYSQL_IDENTIFIER = "mysql";
	String MONGO_IDENTIFIER = "mongo";
	String CLASS_LOADER_IDENTIFIER = "java.net.URL";
	
	/** MSSQL FIELD CONSTANTS */
	String MSSQL_CURRENT_OBJECT = "this$0";
	String MSSQL_BATCH_STATEMENT_BUFFER_FIELD = "batchStatementBuffer";
	String MSSQL_SQL_FIELD = "sql";
	String MSSQL_CONNECTION_FIELD = "connection";
	String MSSQL_ACTIVE_CONNECTION_PROP_FIELD = "activeConnectionProperties";
	String MSSQL_STATEMENT_FIELD = "stmt";
	String MSSQL_USER_SQL_FIELD = "userSQL";
	String MSSQL_IN_OUT_PARAM_FIELD = "inOutParam";
	String MSSQL_BATCH_PARAM_VALUES_FIELD = "batchParamValues";
	String MSSQL_INPUT_DTV_FIELD = "inputDTV";
	String MSSQL_IMPL_FIELD = "impl";
	String MSSQL_VALUE_FIELD = "value";

	/** MSSQL CLASS CONSTANTS */
	String MSSQL_SERVER_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement";
	String MSSQL_PREPARED_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement";
	String MSSQL_PREPARED_BATCH_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement.PrepStmtBatchExecCmd";
	String MSSQL_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtExecCmd";
	String MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtBatchExecCmd";

	String MYSQL_PREPARED_STATEMENT = "PreparedStatement";

	/** Mongo constants */

	String MONGO_NAMESPACE_FIELD = "namespace";
	String MONGO_COMMAND_FIELD = "command";
	String MONGO_PAYLOAD_FIELD = "payload";
	String MONGO_DELETE_REQUEST_FIELD = "deleteRequests";
	String MOGNO_ELEMENT_DATA_FIELD = "elementData";
	String MONGO_FILTER_FIELD = "filter";
	String MONGO_MULTIPLE_UPDATES_FIELD = "updates";
	String MONGO_SINGLE_UPDATE_FIELD = "update";
	String MONGO_INSERT_REQUESTS_FIELD = "insertRequests";
	String MONGO_DOCUMENT_FIELD = "document";
	String MONGO_WRITE_REQUEST_FIELD = "writeRequests";
	String MONGO_FIELD_NAME_FIELD = "fieldName";

	String MONGO_DELETE_CLASS_FRAGMENT = "Delete";
	String MONGO_UPDATE_CLASS_FRAGMENT = "Update";
	String MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT = "FindAndUpdateOperation";
	String MONGO_INSERT_CLASS_FRAGMENT = "Insert";
	String MONGO_FIND_CLASS_FRAGMENT = "Find";
	String MONGO_COMMAND_CLASS_FRAGMENT = "Command";
	String MONGO_WRITE_CLASS_FRAGMENT = "Write";
	String MONGO_DISTINCT_CLASS_FRAGMENT = "Distinct";

	String MONGO_COLLECTION_WILDCARD = "$cmd";
	String MONGO_COLLECTION_FIELD = "collectionName";
	String MONGO_COMMAND_NAME_FIELD = "commandName";

}