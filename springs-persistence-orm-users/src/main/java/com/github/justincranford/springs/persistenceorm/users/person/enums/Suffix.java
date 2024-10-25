package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum Suffix {
    JR("JR", "Junior"),
    SR("SR", "Senior"),
    II("II", "Second"),
    III("III", "Third"),
    IV("IV", "Fourth"),
    V("V", "Fifth"),
    VI("VI", "Sixth"),
    VII("VII", "Seventh"),
    VIII("VIII", "Eighth"),
    IX("IX", "Ninth"),
    X("X", "Tenth"),
    XI("XI", "Eleventh"),
    XII("XII", "Twelfth"),
    XIII("XIII", "Thirteenth"),
    XIV("XIV", "Fourteenth"),
    XV("XV", "Fifteenth"),
    XVI("XVI", "Sixteenth"),
    XVII("XVII", "Seventeenth"),
    XVIII("XVIII", "Eighteenth"),
    XIX("XIX", "Nineteenth"),
    XX("XX", "Twentieth"),
    ;

    private final String abbreviation;
    private final String value;

    Suffix(final String abbreviation, final String value) {
        this.abbreviation = abbreviation;
        this.value = value;
    }

    public String getAbbreviation() {
        return this.abbreviation;
    }

    public String getvalue() {
        return this.value;
    }
}