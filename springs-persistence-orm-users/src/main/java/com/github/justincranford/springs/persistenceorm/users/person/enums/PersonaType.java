package com.github.justincranford.springs.persistenceorm.users.person.enums;

@SuppressWarnings({"nls", "hiding"})
public enum PersonaType {
    OWNER("OWN", "Owner", "Propriétaire", "Propietario", "Individual or entity who owns the property or business"),
    EMPLOYEE("EMP", "Employee", "Employé", "Empleado", "Staff member or worker"),
    PARTNER("PTN", "Partner", "Partenaire", "Socio", "Business or organizational partner"),
    VISITOR("VIS", "Visitor", "Visiteur", "Visitante", "Temporary visitor or non-resident"),
    GUEST("GST", "Guest", "Invité", "Huésped", "Guest, usually invited or temporary"),
    REGISTERED("REG", "Registered", "Enregistré", "Registrado", "Registered user or customer"),

    // Additional personas
    CUSTOMER("CUS", "Customer", "Client", "Cliente", "Regular customer or client"),
    CONTRACTOR("CTR", "Contractor", "Entrepreneur", "Contratista", "Independent contractor or service provider"),
    MANAGER("MGR", "Manager", "Gestionnaire", "Gerente", "Manager or supervisor"),
    INTERN("INT", "Intern", "Stagiaire", "Practicante", "Temporary intern or trainee"),
    SUPERVISOR("SUP", "Supervisor", "Superviseur", "Supervisor", "Supervisor or overseer"),
    ADMINISTRATOR("ADM", "Administrator", "Administrateur", "Administrador", "Administrative personnel"),
    CONSULTANT("CON", "Consultant", "Consultant", "Consultor", "Consultant or advisor"),
    FAMILY_MEMBER("FAM", "Family Member", "Membre de la famille", "Familiar", "Relative or family member"),
    FRIEND("FRD", "Friend", "Ami", "Amigo", "Friend or acquaintance"),
    SUPPLIER("SUPL", "Supplier", "Fournisseur", "Proveedor", "Goods or services supplier"),
    STAKEHOLDER("STK", "Stakeholder", "Partie prenante", "Parte interesada", "Stakeholder or invested party"),
    DIRECTOR("DIR", "Director", "Directeur", "Director", "Company or organization director"),
    SHAREHOLDER("SHR", "Shareholder", "Actionnaire", "Accionista", "Investor or equity holder"),
    VOLUNTEER("VOL", "Volunteer", "Bénévole", "Voluntario", "Person offering unpaid service"),
    STUDENT("STU", "Student", "Étudiant", "Estudiante", "Student or learner"),
    RESIDENT("RES", "Resident", "Résident", "Residente", "Long-term resident"),
    INVESTOR("INV", "Investor", "Investisseur", "Inversor", "Person or group investing in the entity"),
    LICENSEE("LIC", "Licensee", "Licencié", "Licenciatario", "Holder of a license or permit"),
    DISTRIBUTOR("DIS", "Distributor", "Distributeur", "Distribuidor", "Entity or person distributing goods"),
    ATTENDEE("ATT", "Attendee", "Participant", "Asistente", "Event or meeting attendee"),
    VIP("VIP", "VIP", "VIP", "VIP", "Very important person"),
    CANDIDATE("CAN", "Candidate", "Candidat", "Candidato", "Job or position applicant"),
    TENANT("TEN", "Tenant", "Locataire", "Inquilino", "Property tenant or lessee"),
    BENEFICIARY("BEN", "Beneficiary", "Bénéficiaire", "Beneficiario", "Person receiving benefits"),
    EXECUTIVE("EXE", "Executive", "Cadre", "Ejecutivo", "Executive level employee"),
    AGENT("AGT", "Agent", "Agent", "Agente", "Agent or representative");

    private final String abbreviation;
    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    PersonaType(String abbreviation, String english, String french, String spanish, String description) {
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
