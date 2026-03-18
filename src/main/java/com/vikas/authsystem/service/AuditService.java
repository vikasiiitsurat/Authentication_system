package com.vikas.authsystem.service;

import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.AuditLog;
import com.vikas.authsystem.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final String UNKNOWN_DEVICE = "unknown-device";
    private static final String UNKNOWN_IP = "unknown-ip";

    private final AuditLogRepository auditLogRepository;
    private final TransactionTemplate transactionTemplate;

    public AuditService(AuditLogRepository auditLogRepository, PlatformTransactionManager transactionManager) {
        this.auditLogRepository = auditLogRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        // Audit persistence must not share the caller transaction or auth flows could fail on audit errors.
        this.transactionTemplate.setPropagationBehaviorName("PROPAGATION_REQUIRES_NEW");
    }

    public void recordEvent(AuditAction action, UUID userId, String deviceId, String ipAddress) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUserId(userId);
        auditLog.setAction(action);
        auditLog.setDeviceId(normalizeDeviceId(deviceId));
        auditLog.setIpAddress(normalizeIpAddress(ipAddress));
        auditLog.setTimestamp(Instant.now());

        transactionTemplate.executeWithoutResult(status -> {
            try {
                auditLogRepository.saveAndFlush(auditLog);
                // Structured fields keep audit events easy to filter in centralized logging systems.
                log.info(
                        "audit_event action={} userId={} deviceId={} ipAddress={}",
                        action,
                        userId,
                        auditLog.getDeviceId(),
                        auditLog.getIpAddress()
                );
            } catch (RuntimeException ex) {
                status.setRollbackOnly();
                log.error(
                        "audit_event_persist_failed action={} userId={} deviceId={} ipAddress={} error={}",
                        action,
                        userId,
                        auditLog.getDeviceId(),
                        auditLog.getIpAddress(),
                        ex.getMessage()
                );
            }
        });
    }

    private String normalizeDeviceId(String deviceId) {
        return (deviceId == null || deviceId.isBlank()) ? UNKNOWN_DEVICE : deviceId.trim();
    }

    private String normalizeIpAddress(String ipAddress) {
        return (ipAddress == null || ipAddress.isBlank()) ? UNKNOWN_IP : ipAddress.trim();
    }
}
