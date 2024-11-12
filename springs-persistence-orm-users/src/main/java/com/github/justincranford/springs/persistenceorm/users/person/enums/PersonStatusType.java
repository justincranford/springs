package com.github.justincranford.springs.persistenceorm.users.person.enums;

public enum PersonStatusType { 
    ACT("Activated", "Activé", "Activado", "The account is active and fully functional."),
    SUS("Suspended", "Suspendu", "Suspendido", "The account is temporarily suspended."),
    LCK("Locked", "Verrouillé", "Bloqueado", "The account is locked and requires user action to unlock."),
    DIS("Disabled", "Désactivé", "Desactivado", "The account is disabled and cannot be accessed."),
    DEL("Deleted", "Supprimé", "Eliminado", "The account has been deleted."),
    PEN("Pending", "En attente", "Pendiente", "The account is pending approval."),
    APP("Approved", "Approuvé", "Aprobado", "The account has been approved."),
    REJ("Rejected", "Rejeté", "Rechazado", "The account has been rejected."),
    VER("Verified", "Vérifié", "Verificado", "The account has been verified."),
    EXP("Expired", "Expiré", "Caducado", "The account has expired."),
    INA("Inactive", "Inactif", "Inactivo", "The account is currently inactive."),
    CLO("Closed", "Fermé", "Cerrado", "The account is closed."),
    ARC("Archived", "Archivé", "Archivado", "The account is archived."),
    DOR("Dormant", "Dormant", "Inactivo", "The account is dormant."),
    MAI("Maintenance", "Maintenance", "Mantenimiento", "The account is under maintenance."),
    SFC("Suspended for Compliance", "Suspendu pour conformité", "Suspendido por cumplimiento", "The account is suspended for compliance reasons."),
    SFF("Suspended for Fraud", "Suspendu pour fraude", "Suspendido por fraude", "The account is suspended due to fraudulent activity."),
    FLG("Flagged", "Signalé", "Marcado", "The account has been flagged for review."),
    PRO("Processing", "Traitement", "Procesando", "The account is currently being processed."),
    RES("Restored", "Restauré", "Restaurado", "The account has been restored."),
    LFS("Locked for Security", "Verrouillé pour des raisons de sécurité", "Bloqueado por seguridad", "The account is locked due to security concerns."),
    LBA("Locked by Admin", "Verrouillé par l'administrateur", "Bloqueado por el administrador", "The account is locked by an administrator."),
    WLT("Waitlisted", "Liste d'attente", "En lista de espera", "The account is on a waitlist."),
    RAC("Reactivated", "Réactivé", "Reactivado", "The account has been reactivated."),
    TRF("Transferred", "Transféré", "Transferido", "The account has been transferred."),
    LEX("Limit Exceeded", "Limite dépassée", "Límite excedido", "The account has exceeded its limits."),
    TOU("Timeout", "Délai d'attente", "Tiempo de espera", "The account has timed out."),
    PDD("Pending Deletion", "En attente de suppression", "Pendiente de eliminación", "The account is pending deletion."),
    ;

    private final String english;
    private final String french;
    private final String spanish;
    private final String description;

    PersonStatusType(final String _english, final String _french, final String _spanish, final String _description) {
        this.english = _english;
        this.french = _french;
        this.spanish = _spanish;
        this.description = _description;
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

    public String getdescription() {
        return this.description;
    }
}
