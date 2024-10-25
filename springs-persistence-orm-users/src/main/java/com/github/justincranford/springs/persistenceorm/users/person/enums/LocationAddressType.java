package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum LocationAddressType {
    HOME("HME", "Home", "Domicile", "Casa", "Primary residence"),
    WORK("WRK", "Work", "Travail", "Trabajo", "Workplace address"),
    PO_BOX("POB", "P.O. Box", "Boîte postale", "Apartado postal", "Postal box address"),
    VACATION("VAC", "Vacation", "Vacances", "Vacaciones", "Vacation home or location"),
    OTHER("OTH", "Other", "Autre", "Otro", "Other type of address"),

    // Additional common address types
    BILLING("BIL", "Billing", "Facturation", "Facturación", "Billing address"),
    SHIPPING("SHP", "Shipping", "Expédition", "Envío", "Shipping address"),
    LEGAL("LEG", "Legal", "Légal", "Legal", "Legal residence or office"),
    PERMANENT("PRM", "Permanent", "Permanent", "Permanente", "Permanent address"),
    TEMPORARY("TMP", "Temporary", "Temporaire", "Temporal", "Temporary address"),

    // Extended address types with abbreviations
    FAMILY("FAM", "Family", "Famille", "Familia", "Family home"),
    FRIEND("FRD", "Friend", "Ami", "Amigo", "Friend’s address"),
    BUSINESS("BUS", "Business", "Affaires", "Negocios", "Business address"),
    OFFICE("OFF", "Office", "Bureau", "Oficina", "Office location"),
    SCHOOL("SCH", "School", "École", "Escuela", "School address"),
    PRIMARY("PRI", "Primary", "Primaire", "Primario", "Primary address"),
    SECONDARY("SEC", "Secondary", "Secondaire", "Secundario", "Secondary address"),
    MAILING("MLG", "Mailing", "Postal", "Correo", "Mailing address"),
    STORAGE("STR", "Storage", "Stockage", "Almacenaje", "Storage location"),
    EMERGENCY("EMG", "Emergency", "Urgence", "Emergencia", "Emergency contact address"),

    // Additional specific address types
    BRANCH("BRC", "Branch", "Succursale", "Sucursal", "Branch office"),
    CAMPUS("CMP", "Campus", "Campus", "Campus", "Campus location"),
    WAREHOUSE("WHR", "Warehouse", "Entrepôt", "Almacén", "Warehouse address"),
    CLINIC("CLN", "Clinic", "Clinique", "Clínica", "Clinic address"),
    OUTPOST("OTP", "Outpost", "Avant-poste", "Puesto", "Outpost or remote site"),
    RESIDENCE("RES", "Residence", "Résidence", "Residencia", "Residence address"),
    CLIENT("CLT", "Client", "Client", "Cliente", "Client address"),
    SUPPLIER("SUP", "Supplier", "Fournisseur", "Proveedor", "Supplier address"),
    CONTRACTOR("CTR", "Contractor", "Entrepreneur", "Contratista", "Contractor’s address"),
    COURT("CRT", "Court", "Tribunal", "Corte", "Court address"),
    EMBASSY("EMB", "Embassy", "Ambassade", "Embajada", "Embassy location"),
    CONSULATE("CON", "Consulate", "Consulat", "Consulado", "Consulate address"),
    WORKSHOP("WRK", "Workshop", "Atelier", "Taller", "Workshop location"),
    LABORATORY("LAB", "Laboratory", "Laboratoire", "Laboratorio", "Laboratory address"),
    HEADQUARTERS("HQ", "Headquarters", "Siège", "Sede", "Headquarters location"),
    RESEARCH("RSC", "Research", "Recherche", "Investigación", "Research facility");

    private final String abbreviation;
    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    LocationAddressType(String abbreviation, String english, String french, String spanish, String description) {
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