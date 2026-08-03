//! Icon service — image icon lookups.
//!
//! The first of the daemon's own services to move off tonic (CORE-68). It
//! reaches nothing but `dimicon`, so it is the cheapest place to prove the
//! pattern: the handler body is unchanged, only the trait it implements and
//! the router it registers on differ.

use arcbox_connect::v1 as pb;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

struct ResolvedIcon(Option<dimicon::IconSource>);

impl From<ResolvedIcon> for pb::GetImageIconResponse {
    fn from(resolved: ResolvedIcon) -> Self {
        match resolved.0 {
            Some(source) => {
                let name = match &source {
                    dimicon::IconSource::DockerHubLogo { .. } => "docker_hub_logo",
                    dimicon::IconSource::DockerHubOrgGravatar { .. } => "docker_hub_org_gravatar",
                    dimicon::IconSource::DockerOfficialImage { .. } => "docker_official_image",
                    dimicon::IconSource::GhcrAvatar { .. } => "ghcr_avatar",
                    dimicon::IconSource::Devicon { .. } => "devicon",
                    dimicon::IconSource::Custom { .. } => "custom",
                    _ => "unknown",
                };
                Self {
                    url: source.url().to_string(),
                    source: name.to_string(),
                    ..Default::default()
                }
            }
            None => Self {
                url: String::new(),
                source: "not_found".to_string(),
                ..Default::default()
            },
        }
    }
}

/// Icon service implementation — delegates to `dimicon` for image icon lookups.
pub struct IconServiceImpl {
    icon_service: dimicon::IconService,
}

impl Default for IconServiceImpl {
    fn default() -> Self {
        Self {
            icon_service: dimicon::IconService::new(),
        }
    }
}

impl IconServiceImpl {
    /// Creates a new icon service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves an icon for a fully-qualified image name.
    ///
    /// The RPC method is a thin wrapper over this. Keeping the lookup on an
    /// inherent method lets tests exercise resolution without constructing a
    /// request envelope, which is what they actually care about.
    ///
    /// # Errors
    ///
    /// Returns `internal` if the lookup itself fails; an image with no known
    /// icon is a successful response with `source = "not_found"`.
    pub async fn resolve(&self, fqin: &str) -> Result<pb::GetImageIconResponse, ConnectError> {
        let icon = self
            .icon_service
            .get_icon(fqin)
            .await
            .map_err(|e| ConnectError::internal(e.to_string()))?;
        Ok(ResolvedIcon(icon).into())
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::IconService for IconServiceImpl {
    async fn get_image_icon(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::GetImageIconRequest>,
    ) -> ServiceResult<pb::GetImageIconResponse> {
        Response::ok(self.resolve(request.fqin).await?)
    }
}
