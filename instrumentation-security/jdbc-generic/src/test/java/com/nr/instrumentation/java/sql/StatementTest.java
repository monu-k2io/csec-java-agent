package com.nr.instrumentation.java.sql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.h2.jdbc.JdbcStatement;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.sql", "java.sql" })

public class StatementTest {
    private static final String DB_DRIVER = "org.h2.Driver";
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static final Connection CONNECTION = getDBConnection();

    private static List<String> QUERIES = new ArrayList<>();

    private static AtomicInteger id = new AtomicInteger(3);

    @AfterClass
    public static void teardown() throws SQLException {
        CONNECTION.close();
    }

    private static Connection getDBConnection() {
        Connection dbConnection = null;
        try {
            Class.forName(DB_DRIVER);
            dbConnection = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
            return dbConnection;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dbConnection;
    }

    @BeforeClass
    public static void initData() throws SQLException {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USER(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("TRUNCATE TABLE USER");
        QUERIES.add("INSERT INTO USER(id, first_name, last_name) VALUES(1, 'john', 'doe')");
        QUERIES.add("select * from USER");
        QUERIES.add("UPDATE USER SET last_name='Doe' WHERE id=1");
        // set up data in h2
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(0));
        stmt.execute(QUERIES.get(1));
        stmt.execute(QUERIES.get(2));
        stmt.close();
    }

    @Test
    public void testExecuteQuery() throws SQLException {
        executeQuery();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeQuery", operation.getMethodName());
    }

    @Test
    public void testExecuteUpdate() throws SQLException {
        executeUpdate();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeUpdate", operation.getMethodName());
    }


    @Test
    public void testExecute() throws SQLException {
        execute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecuteUpdate2() throws SQLException {
        executeUpdate2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeUpdate", operation.getMethodName());
    }

    @Test
    public void testExecuteUpdate3() throws SQLException {
        executeUpdate3();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeUpdate", operation.getMethodName());
    }

    @Test
    public void testExecute2() throws SQLException {
        execute2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }


    @Test
    public void testExecuteUpdate4() throws SQLException {
        executeUpdate4();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeUpdate", operation.getMethodName());
    }


    @Test
    public void testExecute3() throws SQLException {
        execute3();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecute4() throws SQLException {
        execute4();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void executeQuery() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeQuery(QUERIES.get(3));
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void executeUpdate() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4));
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void execute() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3));
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void executeUpdate2() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4), 1);
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void executeUpdate3() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4), new int[] { 1, 2 });
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void execute2() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3), 2);
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void executeUpdate4() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4), new String[] { "id", "first_name" });
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void execute3() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3), new String[] { "1", "2" });
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void execute4() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3), new int[] { 1, 2 });
        stmt.close();
    }
}
