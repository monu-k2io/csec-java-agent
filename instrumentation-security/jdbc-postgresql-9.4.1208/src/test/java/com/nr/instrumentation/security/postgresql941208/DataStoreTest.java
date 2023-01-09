package com.nr.instrumentation.security.postgresql941208;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.postgresql.jdbc2.optional.ConnectionPool;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.SQLException;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DataStoreTest {
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    @ClassRule
    public static PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer("postgres:11.1")
            .withDatabaseName("test")
            .withUsername(DB_USER)
            .withPassword(DB_PASSWORD);
    private static Connection CONNECTION;

    @AfterClass
    public static void cleanup() throws SQLException {
        if (CONNECTION != null) {
            CONNECTION.close();
        }
    }

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }

    private void getConnection() throws SQLException {
        ConnectionPool baseDataSource = new ConnectionPool();
        baseDataSource.setUrl(postgreSQLContainer.getJdbcUrl());
        baseDataSource.setDatabaseName("test");
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
