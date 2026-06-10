#[derive(Debug, Clone, Default)]
pub struct A2aPartnerPolicy {
    partner_id: String,
    required_tenant: Option<String>,
    required_skills: Vec<String>,
    required_security_scheme_names: Vec<String>,
    allowed_interface_origins: Vec<String>,
}

impl A2aPartnerPolicy {
    #[must_use]
    pub fn new(partner_id: impl Into<String>) -> Self {
        Self {
            partner_id: partner_id.into(),
            required_tenant: None,
            required_skills: Vec::new(),
            required_security_scheme_names: Vec::new(),
            allowed_interface_origins: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_required_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.required_tenant = Some(tenant.into());
        self
    }

    #[must_use]
    pub fn require_skill(mut self, skill_id: impl Into<String>) -> Self {
        let skill_id = skill_id.into();
        if !skill_id.trim().is_empty()
            && !self.required_skills.iter().any(|existing| existing == &skill_id)
        {
            self.required_skills.push(skill_id);
        }
        self
    }

    #[must_use]
    pub fn require_security_scheme(mut self, scheme_name: impl Into<String>) -> Self {
        let scheme_name = scheme_name.into();
        if !scheme_name.trim().is_empty()
            && !self
                .required_security_scheme_names
                .iter()
                .any(|existing| existing == &scheme_name)
        {
            self.required_security_scheme_names.push(scheme_name);
        }
        self
    }

    #[must_use]
    pub fn allow_interface_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        if !origin.trim().is_empty()
            && !self
                .allowed_interface_origins
                .iter()
                .any(|existing| existing == &origin)
        {
            self.allowed_interface_origins.push(origin);
        }
        self
    }
}

