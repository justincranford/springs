package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum EmailAddressType {
    PERSONAL("PER", "Personal", "Personnel", "Personal", "Personal email address"),
    WORK("WRK", "Work", "Professionnel", "Trabajo", "Work email address"),
    FAMILY("FAM", "Family", "Famille", "Familia", "Family email address"),
    GROUP("GRP", "Group", "Groupe", "Grupo", "Group email for shared access"),
    SCHOOL("SCH", "School", "École", "Escuela", "School or academic email address"),
    BUSINESS("BUS", "Business", "Affaires", "Negocios", "Business or company email"),
    CUSTOMER_SERVICE("CST", "Customer Service", "Service client", "Atención al cliente", "Customer service email address"),
    TECH_SUPPORT("SUP", "Tech Support", "Assistance technique", "Soporte técnico", "Technical support email"),
    CONTACT("CNT", "Contact", "Contact", "Contacto", "General contact email"),
    BILLING("BIL", "Billing", "Facturation", "Facturación", "Billing or payment-related email"),
    INVOICES("INV", "Invoices", "Factures", "Facturas", "Invoices and receipts email"),
    ALERTS("ALR", "Alerts", "Alertes", "Alertas", "Alert or notification email"),
    SALES("SAL", "Sales", "Ventes", "Ventas", "Sales and promotions email"),
    ADVERTISEMENT("ADV", "Advertisement", "Publicité", "Publicidad", "Advertising and marketing email"),
    NOTIFICATIONS("NOT", "Notifications", "Notifications", "Notificaciones", "General notifications email"),
    OTHER("OTH", "Other", "Autre", "Otro", "Other or miscellaneous email"),

    // Additional specific types
    NEWSLETTER("NLT", "Newsletter", "Bulletin", "Boletín", "Email for newsletters"),
    PROMOTIONS("PRM", "Promotions", "Promotions", "Promociones", "Promotional offers and deals"),
    SECURITY("SEC", "Security", "Sécurité", "Seguridad", "Security and login notifications"),
    ADMIN("ADM", "Admin", "Administratif", "Administración", "Administrative email"),
    LEGAL("LGL", "Legal", "Juridique", "Legal", "Legal correspondence email"),
    HR("HR", "HR", "RH", "RRHH", "Human Resources email"),
    ACCOUNTING("ACC", "Accounting", "Comptabilité", "Contabilidad", "Accounting department email"),
    COMPLIANCE("CMP", "Compliance", "Conformité", "Cumplimiento", "Compliance and regulatory email"),
    REGISTRATION("REG", "Registration", "Inscription", "Registro", "Registration confirmation email"),
    EVENTS("EVT", "Events", "Événements", "Eventos", "Event-related email"),
    FEEDBACK("FDB", "Feedback", "Retour", "Retroalimentación", "Feedback and suggestions email"),
    PRESS("PRS", "Press", "Presse", "Prensa", "Press inquiries email"),
    SUPPORT("SUP", "Support", "Soutien", "Apoyo", "General support email"),
    PARTNERS("PRT", "Partners", "Partenaires", "Socios", "Partners and affiliates email"),
    INVESTORS("INV", "Investors", "Investisseurs", "Inversores", "Investor relations email"),
    DONATIONS("DNT", "Donations", "Dons", "Donaciones", "Donation and charity email");

    private final String abbreviation;
    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    EmailAddressType(String abbreviation, String english, String french, String spanish, String description) {
        this.abbreviation = abbreviation;
        this.english = english;
        this.french = french;
        this.spanish = spanish;
        this.description = description;
    }

	public String getAbbreviation() {
		return this.abbreviation;
	}

	public String getEnglishName() {
		return this.english;
	}

	public String getFrenchName() {
		return this.french;
	}

	public String getSpanishName() {
		return this.spanish;
	}

	public String getShortDescription() {
		return this.description;
	}
}

