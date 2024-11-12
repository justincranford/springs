package com.github.justincranford.springs.persistenceorm.clients.client.enums;

public enum ClientType {
    OWN("Owner", "Propriétaire", "Propietario", "Individual or entity who owns the property or business"),
    EMP("Employee", "Employé", "Empleado", "Staff member or worker"),
    PTN("Partner", "Partenaire", "Socio", "Business or organizational partner"),
    VIS("Visitor", "Visiteur", "Visitante", "Temporary visitor or non-resident"),
    GST("Guest", "Invité", "Huésped", "Guest, usually invited or temporary"),
    REG("Registered", "Enregistré", "Registrado", "Registered user or customer"),

    // Additional clients
    CUS("Customer", "Client", "Cliente", "Regular customer or client"),
    CTR("Contractor", "Entrepreneur", "Contratista", "Independent contractor or service provider"),
    MGR("Manager", "Gestionnaire", "Gerente", "Manager or supervisor"),
    INT("Intern", "Stagiaire", "Practicante", "Temporary intern or trainee"),
    SUP("Supervisor", "Superviseur", "Supervisor", "Supervisor or overseer"),
    ADM("Administrator", "Administrateur", "Administrador", "Administrative personnel"),
    OPR("Operator", "?", "?", "Operator personnel"),
    CON("Consultant", "Consultant", "Consultor", "Consultant or advisor"),
    FAM("Family Member", "Membre de la famille", "Familiar", "Relative or family member"),
    FRD("Friend", "Ami", "Amigo", "Friend or acquaintance"),
    SUPL("Supplier", "Fournisseur", "Proveedor", "Goods or services supplier"),
    STK("Stakeholder", "Partie prenante", "Parte interesada", "Stakeholder or invested party"),
    DIR("Director", "Directeur", "Director", "Company or organization director"),
    SHR("Shareholder", "Actionnaire", "Accionista", "Investor or equity holder"),
    VOL("Volunteer", "Bénévole", "Voluntario", "Person offering unpaid service"),
    STU("Student", "Étudiant", "Estudiante", "Student or learner"),
    RES("Resident", "Résident", "Residente", "Long-term resident"),
    INV("Investor", "Investisseur", "Inversor", "Person or group investing in the entity"),
    LIC("Licensee", "Licencié", "Licenciatario", "Holder of a license or permit"),
    DIS("Distributor", "Distributeur", "Distribuidor", "Entity or person distributing goods"),
    ATT("Attendee", "Participant", "Asistente", "Event or meeting attendee"),
    VIP("VIP", "VIP", "VIP", "Very important person"),
    CAN("Candidate", "Candidat", "Candidato", "Job or position applicant"),
    TEN("Tenant", "Locataire", "Inquilino", "Property tenant or lessee"),
    BEN("Beneficiary", "Bénéficiaire", "Beneficiario", "Person receiving benefits"),
    EXE("Executive", "Cadre", "Ejecutivo", "Executive level employee"),
    AGT("Agent", "Agent", "Agente", "Agent or representative");

    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    ClientType(final String _english, final String _french, final String _spanish, final String _description) {
        this.english = _english;
        this.french = _french;
        this.spanish = _spanish;
        this.description = _description;
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
