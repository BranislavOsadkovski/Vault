package com.ControlSystem.service;

import lombok.Getter;

@Getter
public enum XmlSigningType {

    BES("Basic electronic signature"),
    BES_T("Electronic signature with time");

    private final String fullName;

    XmlSigningType(String fullName) {
        this.fullName = fullName;
    }
}
