package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum LocationAddressType {
    HME("Home", "Domicile", "Casa", "Primary residence"),
    POB("P.O. Box", "Boîte postale", "Apartado postal", "Postal box address"),
    VAC("Vacation", "Vacances", "Vacaciones", "Vacation home or location"),
    OTH("Other", "Autre", "Otro", "Other type of address"),

    // Additional common address types
    BIL("Billing", "Facturation", "Facturación", "Billing address"),
    SHP("Shipping", "Expédition", "Envío", "Shipping address"),
    LEG("Legal", "Légal", "Legal", "Legal residence or office"),
    PRM("Permanent", "Permanent", "Permanente", "Permanent address"),
    TMP("Temporary", "Temporaire", "Temporal", "Temporary address"),

    // Extended address types with abbreviations
    FAM("Family", "Famille", "Familia", "Family home"),
    FRD("Friend", "Ami", "Amigo", "Friend’s address"),
    BUS("Business", "Affaires", "Negocios", "Business address"),
    OFF("Office", "Bureau", "Oficina", "Office location"),
    SCH("School", "École", "Escuela", "School address"),
    PRI("Primary", "Primaire", "Primario", "Primary address"),
    SEC("Secondary", "Secondaire", "Secundario", "Secondary address"),
    MLG("Mailing", "Postal", "Correo", "Mailing address"),
    STR("Storage", "Stockage", "Almacenaje", "Storage location"),
    EMG("Emergency", "Urgence", "Emergencia", "Emergency contact address"),

    // Additional specific address types
    BRC("Branch", "Succursale", "Sucursal", "Branch office"),
    CMP("Campus", "Campus", "Campus", "Campus location"),
    WHR("Warehouse", "Entrepôt", "Almacén", "Warehouse address"),
    CLN("Clinic", "Clinique", "Clínica", "Clinic address"),
    OTP("Outpost", "Avant-poste", "Puesto", "Outpost or remote site"),
    RES("Residence", "Résidence", "Residencia", "Residence address"),
    CLT("Client", "Client", "Cliente", "Client address"),
    SUP("Supplier", "Fournisseur", "Proveedor", "Supplier address"),
    CTR("Contractor", "Entrepreneur", "Contratista", "Contractor’s address"),
    CRT("Court", "Tribunal", "Corte", "Court address"),
    EMB("Embassy", "Ambassade", "Embajada", "Embassy location"),
    CON("Consulate", "Consulat", "Consulado", "Consulate address"),
    LAB("Laboratory", "Laboratoire", "Laboratorio", "Laboratory address"),
    HQ("Headquarters", "Siège", "Sede", "Headquarters location"),
    RSC("Research", "Recherche", "Investigación", "Research facility");

    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    LocationAddressType(final String english, final String french, final String spanish, final String description) {
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