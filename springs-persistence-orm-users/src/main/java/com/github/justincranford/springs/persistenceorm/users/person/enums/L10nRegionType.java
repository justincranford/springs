package com.github.justincranford.springs.persistenceorm.users.person.enums;

public enum L10nRegionType {
    CN(1_410_000_000L, "中国", "China", "Chine", "China", "A country in East Asia."),
    IN(1_400_000_000L, "भारत", "India", "Inde", "India", "A country in South Asia."),
    US( 331_000_000L, "United States", "United States", "États-Unis", "Estados Unidos", "A country in North America."),
    ID( 273_000_000L, "Indonesia", "Indonesia", "Indonésie", "Indonesia", "A country in Southeast Asia."),
    PK( 240_000_000L, "پاکستان", "Pakistan", "Pakistan", "Pakistán", "A country in South Asia."),
    BR( 213_000_000L, "Brasil", "Brazil", "Brésil", "Brasil", "A country in South America."),
    NG( 206_000_000L, "Nigeria", "Nigeria", "Nigéria", "Nigeria", "A country in West Africa."),
    BD( 166_000_000L, "বাংলাদেশ", "Bangladesh", "Bangladesh", "Bangladés", "A country in South Asia."),
    RU( 146_000_000L, "Россия", "Russia", "Russie", "Rusia", "A country in Eurasia."),
    MX( 126_000_000L, "México", "Mexico", "Mexique", "México", "A country in North America."),
    JP( 126_000_000L, "日本", "Japan", "Japon", "Japón", "An island nation in East Asia."),
    PH( 112_000_000L, "Pilipinas", "Philippines", "Philippines", "Filipinas", "A country in Southeast Asia."),
    VN(  97_000_000L, "Việt Nam", "Vietnam", "Vietnam", "Vietnam", "A country in Southeast Asia."),
    TR(  85_000_000L, "Türkiye", "Turkey", "Turquie", "Turquía", "A transcontinental country."),
    DE(  83_000_000L, "Deutschland", "Germany", "Allemagne", "Alemania", "A country in Europe."),
    TH(  70_000_000L, "ประเทศไทย", "Thailand", "Thaïlande", "Tailandia", "A country in Southeast Asia."),
    UK(  67_000_000L, "United Kingdom", "United Kingdom", "Royaume-Uni", "Reino Unido", "A country in Europe."),
    FR(  65_000_000L, "France", "France", "France", "Francia", "A country in Europe."),
    IT(  60_000_000L, "Italia", "Italy", "Italie", "Italia", "A country in Europe."),
    ZA(  60_000_000L, "South Africa", "South Africa", "Afrique du Sud", "Sudáfrica", "A country in Africa."),
    KE(  54_000_000L, "Kenya", "Kenya", "Kenya", "Kenia", "A country in East Africa."),
    KR(  51_000_000L, "대한민국", "South Korea", "Corée du Sud", "Corea del Sur", "A country in East Asia."),
    CO(  51_000_000L, "Colombia", "Colombia", "Colombie", "Colombia", "A country in South America."),
    AR(  45_000_000L, "Argentina", "Argentina", "Argentine", "Argentina", "A country in South America."),
    DZ(  44_000_000L, "الجزائر", "Algeria", "Algérie", "Argelia", "A country in North Africa."),
    UA(  41_000_000L, "Україна", "Ukraine", "Ukraine", "Ucrania", "A country in Eastern Europe."),
    MA(  36_000_000L, "المغرب", "Morocco", "Maroc", "Marruecos", "A country in North Africa."),
    MY(  33_000_000L, "Malaysia", "Malaysia", "Malaisie", "Malasia", "A country in Southeast Asia."),
    AU(  25_000_000L, "Australia", "Australia", "Australie", "Australia", "A country in Oceania."),
    CL(  19_000_000L, "Chile", "Chile", "Chili", "Chile", "A country in South America."),
    PE(  33_000_000L, "Perú", "Peru", "Pérou", "Perú", "A country in South America."),
    SE(  10_000_000L, "Sverige", "Sweden", "Suède", "Suecia", "A country in Northern Europe."),
    AE(   9_000_000L, "الإمارات العربية المتحدة", "United Arab Emirates", "Émirats Arabes Unis", "Emiratos Árabes Unidos", "A federation of seven emirates in the Middle East."),
    DK(   5_800_000L, "Danmark", "Denmark", "Danemark", "Dinamarca", "A country in Northern Europe."),
    FI(   5_500_000L, "Suomi", "Finland", "Finlande", "Finlandia", "A country in Northern Europe."),
    NO(   5_000_000L, "Norge", "Norway", "Norvège", "Noruega", "A country in Northern Europe."),
    CY(   1_200_000L, "Κύπρος", "Cyprus", "Chypre", "Chipre", "An island country in the Eastern Mediterranean."),
    LU(     640_000L, "Luxembourg", "Luxembourg", "Luxembourg", "Luxemburgo", "A small landlocked country in Western Europe."),
    MT(     514_000L, "Malta", "Malta", "Malte", "Malta", "An island nation in the Mediterranean."),
    IS(     370_000L, "Ísland", "Iceland", "Islande", "Islandia", "A Nordic island country."),
    AD(     77_000L,  "Andorra", "Andorra", "Andorre", "Andorra", "A small principality in the Pyrenees mountains."),
    MC(     39_000L,  "Monaco", "Monaco", "Monaco", "Mónaco", "A sovereign city-state on the French Riviera."),
    SM(     34_000L,  "San Marino", "San Marino", "Saint-Marin", "San Marino", "A microstate surrounded by Italy."),
    ;

    private final long count;
    private final String localeValue;
    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    L10nRegionType(final long _count, final String _localeValue, final String _english, final String _french, final String _spanish, final String _description) {
        this.count = _count;
        this.localeValue = _localeValue;
        this.english = _english;
        this.french = _french;
        this.spanish = _spanish;
        this.description = _description;
    }

    public long getCount() {
        return this.count;
    }

    public String getLocaleValue() {
        return this.localeValue;
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
