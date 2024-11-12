package com.github.justincranford.springs.persistenceorm.users.person.enums;

public enum SuffixType {
    JR("Junior"),
    SR("Senior"),
    II("Second"),
    III("Third"),
    IV("Fourth"),
    V("Fifth"),
    VI("Sixth"),
    VII("Seventh"),
    VIII("Eighth"),
    IX("Ninth"),
    X("Tenth"),
    XI("Eleventh"),
    XII("Twelfth"),
    XIII("Thirteenth"),
    XIV("Fourteenth"),
    XV("Fifteenth"),
    XVI("Sixteenth"),
    XVII("Seventeenth"),
    XVIII("Eighteenth"),
    XIX("Nineteenth"),
    XX("Twentieth"),
    ;

    private final String value;

    SuffixType(final String _value) {
        this.value = _value;
    }

    public String getvalue() {
        return this.value;
    }
}