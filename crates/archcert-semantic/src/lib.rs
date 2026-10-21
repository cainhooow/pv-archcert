//! Local deterministic replay only. No provider SDK, process launcher, network,
//! credential, signer, runtime or database capability is present.

use archcert_application::semantic::*;
use archcert_domain::Sha256Digest;
use async_trait::async_trait;

/// An operator-provisioned exact replay, never discovered in target source.
pub struct ReplayReviewer {
    request_sha256: Sha256Digest,
    response: Vec<u8>,
}

impl ReplayReviewer {
    /// Pins one bounded response to one exact request. Raw bytes remain private
    /// and are not Debug/Display output. Structured acceptance occurs in application.
    pub fn new(
        request_sha256: Sha256Digest,
        response: Vec<u8>,
    ) -> Result<Self, SemanticReviewError> {
        if response.len() > SemanticLimits::default().response_bytes {
            return Err(SemanticReviewError::Oversized);
        }

        Ok(Self {
            request_sha256,
            response,
        })
    }
}

#[async_trait]
impl SemanticReviewer for ReplayReviewer {
    async fn review(
        &self,
        request: &SemanticReviewRequest,
    ) -> Result<ReviewerOutput, SemanticReviewError> {
        if request.artifact().digest() != &self.request_sha256 {
            return Err(SemanticReviewError::BindingMismatch);
        }

        if request.selection() != &ReviewerSelection::replay() {
            return Err(SemanticReviewError::UnsupportedMetadata);
        }

        if self.response.len() > request.limits().response_bytes {
            return Err(SemanticReviewError::Oversized);
        }

        Ok(ReviewerOutput {
            reported: ReviewerSelection::replay(),
            bytes: self.response.clone(),
            truncated: false,
        })
    }
}

/// Default absence of an authorized provider. It never falls back to a network.
pub struct UnavailableReviewer;

#[async_trait]
impl SemanticReviewer for UnavailableReviewer {
    async fn review(
        &self,
        _: &SemanticReviewRequest,
    ) -> Result<ReviewerOutput, SemanticReviewError> {
        Err(SemanticReviewError::Unavailable)
    }
}
