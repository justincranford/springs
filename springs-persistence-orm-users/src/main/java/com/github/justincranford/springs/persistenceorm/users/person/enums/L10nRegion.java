package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum L10nRegion {
    CN("CN", 1_410_000_000L, "中国", "China", "Chine", "China", "A country in East Asia."),
    IN("IN", 1_400_000_000L, "भारत", "India", "Inde", "India", "A country in South Asia."),
    US("US",  331_000_000L, "United States", "United States", "États-Unis", "Estados Unidos", "A country in North America."),
    ID("ID",  273_000_000L, "Indonesia", "Indonesia", "Indonésie", "Indonesia", "A country in Southeast Asia."),
    PK("PK",  240_000_000L, "پاکستان", "Pakistan", "Pakistan", "Pakistán", "A country in South Asia."),
    BR("BR",  213_000_000L, "Brasil", "Brazil", "Brésil", "Brasil", "A country in South America."),
    NG("NG",  206_000_000L, "Nigeria", "Nigeria", "Nigéria", "Nigeria", "A country in West Africa."),
    BD("BD",  166_000_000L, "বাংলাদেশ", "Bangladesh", "Bangladesh", "Bangladés", "A country in South Asia."),
    RU("RU",  146_000_000L, "Россия", "Russia", "Russie", "Rusia", "A country in Eurasia."),
    MX("MX",  126_000_000L, "México", "Mexico", "Mexique", "México", "A country in North America."),
    JP("JP",  126_000_000L, "日本", "Japan", "Japon", "Japón", "An island nation in East Asia."),
    PH("PH",  112_000_000L, "Pilipinas", "Philippines", "Philippines", "Filipinas", "A country in Southeast Asia."),
    VN("VN",   97_000_000L, "Việt Nam", "Vietnam", "Vietnam", "Vietnam", "A country in Southeast Asia."),
    TR("TR",   85_000_000L, "Türkiye", "Turkey", "Turquie", "Turquía", "A transcontinental country."),
    DE("DE",   83_000_000L, "Deutschland", "Germany", "Allemagne", "Alemania", "A country in Europe."),
    TH("TH",   70_000_000L, "ประเทศไทย", "Thailand", "Thaïlande", "Tailandia", "A country in Southeast Asia."),
    UK("UK",   67_000_000L, "United Kingdom", "United Kingdom", "Royaume-Uni", "Reino Unido", "A country in Europe."),
    FR("FR",   65_000_000L, "France", "France", "France", "Francia", "A country in Europe."),
    IT("IT",   60_000_000L, "Italia", "Italy", "Italie", "Italia", "A country in Europe."),
    ZA("ZA",   60_000_000L, "South Africa", "South Africa", "Afrique du Sud", "Sudáfrica", "A country in Africa."),
    KE("KE",   54_000_000L, "Kenya", "Kenya", "Kenya", "Kenia", "A country in East Africa."),
    KR("KR",   51_000_000L, "대한민국", "South Korea", "Corée du Sud", "Corea del Sur", "A country in East Asia."),
    CO("CO",   51_000_000L, "Colombia", "Colombia", "Colombie", "Colombia", "A country in South America."),
    AR("AR",   45_000_000L, "Argentina", "Argentina", "Argentine", "Argentina", "A country in South America."),
    DZ("DZ",   44_000_000L, "الجزائر", "Algeria", "Algérie", "Argelia", "A country in North Africa."),
    UA("UA",   41_000_000L, "Україна", "Ukraine", "Ukraine", "Ucrania", "A country in Eastern Europe."),
    MA("MA",   36_000_000L, "المغرب", "Morocco", "Maroc", "Marruecos", "A country in North Africa."),
    MY("MY",   33_000_000L, "Malaysia", "Malaysia", "Malaisie", "Malasia", "A country in Southeast Asia."),
    AU("AU",   25_000_000L, "Australia", "Australia", "Australie", "Australia", "A country in Oceania."),
    CL("CL",   19_000_000L, "Chile", "Chile", "Chili", "Chile", "A country in South America."),
    PE("PE",   33_000_000L, "Perú", "Peru", "Pérou", "Perú", "A country in South America."),
    SE("SE",   10_000_000L, "Sverige", "Sweden", "Suède", "Suecia", "A country in Northern Europe."),
    AE("AE",    9_000_000L, "الإمارات العربية المتحدة", "United Arab Emirates", "Émirats Arabes Unis", "Emiratos Árabes Unidos", "A federation of seven emirates in the Middle East."),
    DK("DK",    5_800_000L, "Danmark", "Denmark", "Danemark", "Dinamarca", "A country in Northern Europe."),
    FI("FI",    5_500_000L, "Suomi", "Finland", "Finlande", "Finlandia", "A country in Northern Europe."),
    NO("NO",    5_000_000L, "Norge", "Norway", "Norvège", "Noruega", "A country in Northern Europe."),
    CY("CY",    1_200_000L, "Κύπρος", "Cyprus", "Chypre", "Chipre", "An island country in the Eastern Mediterranean."),
    LU("LU",      640_000L, "Luxembourg", "Luxembourg", "Luxembourg", "Luxemburgo", "A small landlocked country in Western Europe."),
    MT("MT",      514_000L, "Malta", "Malta", "Malte", "Malta", "An island nation in the Mediterranean."),
    IS("IS",      370_000L, "Ísland", "Iceland", "Islande", "Islandia", "A Nordic island country."),
    AD("AD",      77_000L,  "Andorra", "Andorra", "Andorre", "Andorra", "A small principality in the Pyrenees mountains."),
    MC("MC",      39_000L,  "Monaco", "Monaco", "Monaco", "Mónaco", "A sovereign city-state on the French Riviera."),
    SM("SM",      34_000L,  "San Marino", "San Marino", "Saint-Marin", "San Marino", "A microstate surrounded by Italy."),
    ;

    private final String abbreviation;
    private final long count;
    private final String nativeValue;
    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    L10nRegion(String abbreviation, long count, String nativeValue, String english, String french, String spanish, String description) {
        this.abbreviation = abbreviation;
        this.count = count;
        this.nativeValue = nativeValue;
        this.english = english;
        this.french = french;
        this.spanish = spanish;
        this.description = description;
    }

    // Getters
    public String getAbbreviation() {
        return this.abbreviation;
    }

    public long getCount() {
        return this.count;
    }

    public String getNativeValue() {
        return this.nativeValue;
    }

    public String getEnglish() {
        return this.english;
    }

    public String getFrench() {
        return this.french;
    }

    public String getSpanish() {
        return this.spanish;
    }

    public String getDescription() {
        return this.description;
    }
}
