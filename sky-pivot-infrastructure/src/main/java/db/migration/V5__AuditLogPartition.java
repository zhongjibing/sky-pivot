package db.migration;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

@SuppressWarnings("resource")
public class V5__AuditLogPartition extends BaseJavaMigration {

    private static final Logger log = LoggerFactory.getLogger(V5__AuditLogPartition.class);

    @Override
    public void migrate(Context context) throws Exception {
        Connection conn = context.getConnection();
        String productName = conn.getMetaData().getDatabaseProductName();

        if (!"MySQL".equalsIgnoreCase(productName)) {
            log.info("Skipping audit_log partition migration: database is {}, not MySQL", productName);
            return;
        }

        boolean alreadyPartitioned = false;
        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT COUNT(*) > 0 FROM information_schema.partitions " +
                "WHERE table_schema = DATABASE() AND table_name = 'audit_log' AND partition_name IS NOT NULL")) {
            if (rs.next()) {
                alreadyPartitioned = rs.getBoolean(1);
            }
        }

        if (alreadyPartitioned) {
            log.info("audit_log is already partitioned, skipping");
            return;
        }

        log.info("Applying MySQL RANGE partitioning on audit_log by YEAR(created_at)");

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("""
                ALTER TABLE audit_log
                PARTITION BY RANGE (YEAR(created_at)) (
                    PARTITION p2024 VALUES LESS THAN (2025),
                    PARTITION p2025 VALUES LESS THAN (2026),
                    PARTITION p2026 VALUES LESS THAN (2027),
                    PARTITION p2027 VALUES LESS THAN (2028),
                    PARTITION p2028 VALUES LESS THAN (2029),
                    PARTITION p2029 VALUES LESS THAN (2030),
                    PARTITION p_future VALUES LESS THAN MAXVALUE
                )
                """);
        }

        log.info("audit_log RANGE partition migration completed successfully");
    }
}
