//! Local macOS secure-input UI. Authorization remains the kernel UID; a dialog
//! is never evidence of a human or a replacement for distinct execution domains.
use crate::error::{KeydError, Result};
use std::path::Path;
use zeroize::Zeroizing;

pub fn unlock_secret(
    config: &Path,
    vault: &str,
    did: &str,
    kid: &str,
) -> Result<Zeroizing<String>> {
    #[cfg(target_os = "macos")]
    {
        let settings = super::config::ServiceConfig::load(config)?;
        if settings.mode != "macos-boundary-preview" {
            return Err(KeydError::Misuse(
                "native management UI requires macOS boundary mode".into(),
            ));
        }
        // No Agent-controlled executable may collect the management password.
        super::paths::validate_chain(&std::env::current_exe()?, &[0], false)?;
        super::client::Client::connect(config, true)?.capabilities()?;
        super::server::harden_process()?;
        let details = format!("Local preview — protected support is not declared.\nInstance: {}\nService UID: {}\nVault: {vault}\nDID: {did}\nKey: {kid}\n\nUnlock only; no grant is issued. Expires after 120 seconds.", settings.instance_id, settings.service_uid);
        if details.len() > 4096
            || [vault, did, kid]
                .iter()
                .any(|s| s.chars().any(char::is_control))
        {
            return Err(KeydError::Misuse(
                "invalid native UI key description".into(),
            ));
        }
        native::prompt(&details)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (config, vault, did, kid);
        Err(KeydError::Misuse(
            "native management UI is available only on macOS".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use core_foundation_sys::{base::*, dictionary::*, string::*, user_notification::*};
    use std::ffi::c_void;
    use std::ptr;

    struct Owned(CFTypeRef);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) };
        }
    }
    fn owned(value: CFTypeRef) -> Result<Owned> {
        if value.is_null() {
            Err(failed())
        } else {
            Ok(Owned(value))
        }
    }
    fn failed() -> KeydError {
        KeydError::Misuse("native unlock cancelled, unavailable or invalid".into())
    }
    fn string(value: &str) -> Result<Owned> {
        // CF copies the valid UTF-8 bytes; this contains public labels only.
        owned(
            unsafe {
                CFStringCreateWithBytes(
                    ptr::null(),
                    value.as_ptr(),
                    value.len() as CFIndex,
                    kCFStringEncodingUTF8,
                    0,
                )
            }
            .cast(),
        )
    }
    pub(super) fn prompt(details: &str) -> Result<Zeroizing<String>> {
        let labels = [
            string("anp-keyd — Unlock exact key")?,
            string(details)?,
            string("Cancel")?,
            string("Unlock")?,
            string("Passphrase")?,
        ];
        // All keys are framework constants; callback-managed values remain alive
        // through CFDictionaryCreate, which retains them. The notification retains
        // its dictionary. The borrowed response string lives until notification drop.
        unsafe {
            let keys = [
                kCFUserNotificationAlertHeaderKey,
                kCFUserNotificationAlertMessageKey,
                kCFUserNotificationDefaultButtonTitleKey,
                kCFUserNotificationAlternateButtonTitleKey,
                kCFUserNotificationTextFieldTitlesKey,
            ]
            .map(|p| p.cast::<c_void>());
            let values: Vec<_> = labels.iter().map(|v| v.0).collect();
            let dictionary = owned(
                CFDictionaryCreate(
                    ptr::null(),
                    keys.as_ptr(),
                    values.as_ptr(),
                    keys.len() as CFIndex,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                )
                .cast(),
            )?;
            let mut error = 0;
            // Cancel is the default (including Return). Only the explicit alternate
            // Unlock response releases the value; timeout and close fail closed.
            let notification = owned(
                CFUserNotificationCreate(
                    ptr::null(),
                    120.0,
                    kCFUserNotificationCautionAlertLevel | CFUserNotificationSecureTextField(0),
                    &mut error,
                    dictionary.0.cast(),
                )
                .cast(),
            )?;
            if error != 0 {
                return Err(failed());
            }
            let mut flags = 0;
            let status = CFUserNotificationReceiveResponse(
                notification.0 as CFUserNotificationRef,
                120.0,
                &mut flags,
            );
            if status != 0 || flags & 3 != kCFUserNotificationAlternateResponse {
                CFUserNotificationCancel(notification.0 as CFUserNotificationRef);
                return Err(failed());
            }
            let value = CFUserNotificationGetResponseValue(
                notification.0 as CFUserNotificationRef,
                kCFUserNotificationTextFieldValuesKey,
                0,
            );
            if value.is_null() {
                return Err(failed());
            }
            let length = CFStringGetLength(value);
            if length == 0 || length > 1024 {
                return Err(failed());
            }
            let mut bytes = Zeroizing::new(vec![0u8; 4096]);
            let mut used = 0;
            let converted = CFStringGetBytes(
                value,
                CFRange {
                    location: 0,
                    length,
                },
                kCFStringEncodingUTF8,
                0,
                0,
                bytes.as_mut_ptr(),
                bytes.len() as CFIndex,
                &mut used,
            );
            if converted != length || used == 0 {
                return Err(failed());
            }
            // Framework-owned input cannot be guaranteed zeroized. The application
            // owns only this zeroizing copy, never argv/env/stdout or a script pipe.
            let text = std::str::from_utf8(&bytes[..used as usize]).map_err(|_| failed())?;
            Ok(Zeroizing::new(text.to_owned()))
        }
    }
}
