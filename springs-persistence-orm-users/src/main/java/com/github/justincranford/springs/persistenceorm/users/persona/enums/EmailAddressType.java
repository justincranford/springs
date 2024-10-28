package com.github.justincranford.springs.persistenceorm.users.persona.enums;

@SuppressWarnings({"nls", "hiding"})
public enum EmailAddressType {
    PER("Personal", "Personnel", "Personal", "Personal email address"),
    WRK("Work", "Professionnel", "Trabajo", "Work email address"),
    FAM("Family", "Famille", "Familia", "Family email address"),
    GRP("Group", "Groupe", "Grupo", "Group email for shared access"),
    SCH("School", "École", "Escuela", "School or academic email address"),
    BUS("Business", "Affaires", "Negocios", "Business or company email"),
    CST("Customer Service", "Service client", "Atención al cliente", "Customer service email address"),
    SUP("Tech Support", "Assistance technique", "Soporte técnico", "Technical support email"),
    CNT("Contact", "Contact", "Contacto", "General contact email"),
    BIL("Billing", "Facturation", "Facturación", "Billing or payment-related email"),
    ALR("Alerts", "Alertes", "Alertas", "Alert or notification email"),
    SAL("Sales", "Ventes", "Ventas", "Sales and promotions email"),
    ADV("Advertisement", "Publicité", "Publicidad", "Advertising and marketing email"),
    NOT("Notifications", "Notifications", "Notificaciones", "General notifications email"),
    OTH("Other", "Autre", "Otro", "Other or miscellaneous email"),

    // Additional specific types
    NLT("Newsletter", "Bulletin", "Boletín", "Email for newsletters"),
    PRM("Promotions", "Promotions", "Promociones", "Promotional offers and deals"),
    SEC("Security", "Sécurité", "Seguridad", "Security and login notifications"),
    ADM("Admin", "Administratif", "Administración", "Administrative email"),
    LGL("Legal", "Juridique", "Legal", "Legal correspondence email"),
    HR("HR", "RH", "RRHH", "Human Resources email"),
    ACC("Accounting", "Comptabilité", "Contabilidad", "Accounting department email"),
    CMP("Compliance", "Conformité", "Cumplimiento", "Compliance and regulatory email"),
    REG("Registration", "Inscription", "Registro", "Registration confirmation email"),
    EVT("Events", "Événements", "Eventos", "Event-related email"),
    FDB("Feedback", "Retour", "Retroalimentación", "Feedback and suggestions email"),
    PRS("Press", "Presse", "Prensa", "Press inquiries email"),
    PRT("Partners", "Partenaires", "Socios", "Partners and affiliates email"),
    INV("Investors", "Investisseurs", "Inversores", "Investor relations email"),
    DNT("Donations", "Dons", "Donaciones", "Donation and charity email");

    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    EmailAddressType(final String english, final String french, final String spanish, final String description) { 
        this.english = english;
        this.french = french;
        this.spanish = spanish;
        this.description = description;
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

