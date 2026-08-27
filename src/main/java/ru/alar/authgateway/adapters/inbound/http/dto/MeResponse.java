package ru.alar.authgateway.adapters.inbound.http.dto;

public record MeResponse(String subject, String name, String email, String organizationId) {
}
