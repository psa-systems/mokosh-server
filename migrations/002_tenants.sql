-- PMS-128 split: extensions, tenants table, default tenant row.
-- (Originally part of the monolithic 001_initial_schema.sql; see PMS-128.)

-- Mokosh Server Initial Schema
-- This migration creates the core tables for Mokosh Server

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fuzzy text search

-- ============================================================================
-- TENANTS (Multi-tenant support)
-- ============================================================================

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    settings JSONB NOT NULL DEFAULT '{}',
    branding JSONB NOT NULL DEFAULT '{}',
    billing_email VARCHAR(255),
    billing_contact_name VARCHAR(255),
    subscription_plan VARCHAR(50),
    subscription_status VARCHAR(20) DEFAULT 'trialing',
    trial_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);


-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Insert a default tenant for single-tenant mode
INSERT INTO tenants (id, name, slug, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'active')
ON CONFLICT DO NOTHING;
