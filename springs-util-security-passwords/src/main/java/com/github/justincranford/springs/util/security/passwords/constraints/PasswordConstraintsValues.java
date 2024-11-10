package com.github.justincranford.springs.util.security.passwords.constraints;

@SuppressWarnings({"nls"})
public class PasswordConstraintsValues {
	public static final String UPPERS_DEFAULT     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	public static final String LOWERS_DEFAULT     = "abcdefghijklmnopqrstuvwxyz";
	public static final String DIGITS_DEFAULT     = "0123456789";
	public static final String SPECIALS_DEFAULT   = "~`!@#$%^&*()_-+={}[]|\\\"':;?/<>,.";
	public static final String WHITESPACE_DEFAULT = " \t\n\r\f";

	public static final int MIN_LENGTH_MIN              = 12, MIN_LENGTH_DEFAULT              =  12, MIN_LENGTH_MAX              = 128; // OWASP min 12 regular, 16 more sensitive
    public static final int MAX_LENGTH_MIN              = 43, MAX_LENGTH_DEFAULT              = 128, MAX_LENGTH_MAX              = 128; // 32-byte random => 43-char base64
    public static final int MIN_UPPERS_MIN              =  0, MIN_UPPERS_DEFAULT              =   1, MIN_UPPERS_MAX              = 128; // traditional min 1, current recommendation is min 0
    public static final int MAX_UPPERS_MIN              =  0, MAX_UPPERS_DEFAULT              = 128, MAX_UPPERS_MAX              = 128;
    public static final int MIN_LOWERS_MIN              =  0, MIN_LOWERS_DEFAULT              =   1, MIN_LOWERS_MAX              = 128; // traditional min 1, current recommendation is min 0
    public static final int MAX_LOWERS_MIN              =  0, MAX_LOWERS_DEFAULT              = 128, MAX_LOWERS_MAX              = 128;
    public static final int MIN_DIGITS_MIN              =  0, MIN_DIGITS_DEFAULT              =   1, MIN_DIGITS_MAX              = 128; // traditional min 1, current recommendation is min 0
    public static final int MAX_DIGITS_MIN              =  0, MAX_DIGITS_DEFAULT              = 128, MAX_DIGITS_MAX              = 128;
    public static final int MIN_SPECIALS_MIN            =  0, MIN_SPECIALS_DEFAULT            =   1, MIN_SPECIALS_MAX            = 128; // traditional min 1, current recommendation is min 0
    public static final int MAX_SPECIALS_MIN            =  0, MAX_SPECIALS_DEFAULT            = 128, MAX_SPECIALS_MAX            = 128;
    public static final int MIN_WHITESPACE_MIN          =  0, MIN_WHITESPACE_DEFAULT          =   0, MIN_WHITESPACE_MAX          = 128; // Allow spaces to support passphrases
    public static final int MAX_WHITESPACE_MIN          =  0, MAX_WHITESPACE_DEFAULT          =   8, MAX_WHITESPACE_MAX          = 128; // Too many may not be ideal
    public static final int MAX_ANYWHERE_REPEATS_MIN    =  0, MAX_ANYWHERE_REPEATS_DEFAULT    =   3, MAX_ANYWHERE_REPEATS_MAX    = 128;
    public static final int MAX_CONSECUTIVE_REPEATS_MIN =  0, MAX_CONSECUTIVE_REPEATS_DEFAULT =   2, MAX_CONSECUTIVE_REPEATS_MAX = 128;
}
