use poem_openapi::{OpenApi, OpenApiService};

mod admin_agora;
mod admin_fcm;
mod admin_github_auth;
mod admin_google_auth;
mod admin_login;
mod admin_smtp;
mod admin_system;
mod admin_user;
mod archive;
mod bot;
mod datetime;
mod e2e;
mod favorite;
mod group;
mod langid;
mod license;
mod message;
mod message_api;
mod resource;
mod tags;
mod token;
mod user;
mod user_log_action;

pub use admin_agora::AgoraConfig;
pub use admin_fcm::FcmConfig;
pub use admin_login::{LoginConfig, WhoCanSignUp};
pub use admin_smtp::SmtpConfig;
pub use admin_system::{FrontendUrlConfig, Metrics, OrganizationConfig};
pub use admin_user::{User, UserDevice};
pub use archive::Archive;
pub use datetime::DateTime;
pub use e2e::redact_e2e_chat_message_json;
pub use group::{Group, PinnedMessage};
pub use langid::LangId;
pub use message::{
    get_merged_message, BurnAfterReadingGroup, BurnAfterReadingUser, ChatMessage,
    ChatMessagePayload, GroupChangedMessage, HeartbeatMessage, JoinedGroupMessage,
    KickFromGroupMessage, KickFromGroupReason, KickMessage, KickReason, Message, MessageDetail,
    MessageTarget, MessageTargetGroup, MessageTargetUser, MuteGroup, MuteUser, ReadIndexGroup,
    ReadIndexUser, RelatedGroupsMessage, UserJoinedGroupMessage, UserLeavedGroupMessage,
    UserSettingsChangedMessage, UserSettingsMessage, UserState, UserStateChangedMessage,
    UserUpdateLog, UsersStateMessage, UsersUpdateLogMessage,
};
pub use resource::FileMeta;
pub use token::{CurrentUser, Token};
pub use user::{
    CreateUserConflictReason, CreateUserResponse, UpdateUserResponse, UserConflict, UserInfo,
};
pub use user_log_action::UpdateAction;

pub fn create_api_service() -> OpenApiService<impl OpenApi, ()> {
    // poem-openapi OpenApi is implemented for tuples up to 16; nest past that.
    OpenApiService::new(
        (
            (
                token::ApiToken,
                user::ApiUser,
                e2e::ApiE2e,
                group::ApiGroup,
                admin_user::ApiAdminUser,
                resource::ApiResource,
                message_api::ApiMessage,
                favorite::ApiFavorite,
            ),
            (
                license::ApiLicense,
                admin_system::ApiAdminSystem,
                admin_agora::ApiAdminAgora,
                admin_fcm::ApiAdminFirebase,
                admin_smtp::ApiAdminSmtp,
                admin_login::ApiAdminLogin,
                admin_google_auth::ApiAdminGoogleAuth,
                admin_github_auth::ApiAdminGithubAuth,
                bot::ApiBot,
            ),
        ),
        "Voce Chat",
        env!("CARGO_PKG_VERSION"),
    )
}
