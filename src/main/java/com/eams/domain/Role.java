package com.eams.domain;

/**
 * The two roles this system supports.
 * ADMIN   -> can onboard/manage/deactivate users, view everyone.
 * EMPLOYEE -> can only view and update their own profile.
 */
public enum Role {
    ADMIN,
    EMPLOYEE
}
