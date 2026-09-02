use crate::UiText;

/// All static UI copy lives here so translators can work without touching the
/// view or service code. English is the fallback for unknown language codes.
pub fn ui_text(language: &str) -> UiText {
    if language.eq_ignore_ascii_case("ru") || language.eq_ignore_ascii_case("rus") {
        return UiText {
            my_profile: "Мой профиль".into(),
            ready: "Готово".into(),
            conversations: "Чаты".into(),
            search_conversations: "Поиск чатов".into(),
            new_conversation: "Новый чат".into(),
            verified_contact: "Проверенный контакт".into(),
            no_conversations: "Чатов пока нет".into(),
            verified_encrypted: "Проверено · сквозное шифрование".into(),
            load_older: "Загрузить старые сообщения".into(),
            new_conversation_help:
                "Обменяйтесь публичными ключами по доверенному каналу и проверьте отпечаток.".into(),
            contact_bundle: "Публичный ключ контакта".into(),
            contact_fingerprint: "Отпечаток проверенного контакта".into(),
            profile_password: "Пароль вашего профиля".into(),
            verify_add_contact: "Проверить и добавить контакт".into(),
            contact_added: "Контакт добавлен — выберите его, чтобы открыть чат".into(),
            select_conversation: "Выберите чат".into(),
            type_message: "Введите сообщение".into(),
            send: "Отправить".into(),
            paste_encrypted: "Вставьте зашифрованное сообщение".into(),
            receive_pasted: "Получить вставленное".into(),
            unlock: "Разблокировать SafeChat".into(),
            create_profile: "Создать профиль SafeChat".into(),
            unlock_help: "Выберите профиль и введите пароль.".into(),
            create_help: "Создайте отдельную зашифрованную личность для другого пользователя."
                .into(),
            profile_name: "Имя профиля".into(),
            password: "Пароль".into(),
            confirm_password: "Подтвердите пароль".into(),
            create_profile_button: "Создать профиль".into(),
            unlock_profile: "Разблокировать профиль".into(),
            back_to_profiles: "Назад к профилям".into(),
            create_new_profile: "Создать новый профиль".into(),
            fingerprint: "Отпечаток".into(),
            your_fingerprint: "Ваш отпечаток".into(),
            share_bundle: "Передавайте публичный ключ только по доверенному каналу.".into(),
            copy_bundle: "Копировать публичный ключ".into(),
            close: "Закрыть".into(),
        };
    }

    UiText {
        my_profile: "My profile".into(),
        ready: "Ready".into(),
        conversations: "Conversations".into(),
        search_conversations: "Search conversations".into(),
        new_conversation: "New conversation".into(),
        verified_contact: "Verified contact".into(),
        no_conversations: "No conversations yet".into(),
        verified_encrypted: "Verified · end-to-end encrypted".into(),
        load_older: "Load older messages".into(),
        new_conversation_help:
            "Exchange public bundles through a trusted channel, then verify the fingerprint.".into(),
        contact_bundle: "Contact public bundle".into(),
        contact_fingerprint: "Verified contact fingerprint".into(),
        profile_password: "Your profile password".into(),
        verify_add_contact: "Verify and add contact".into(),
        contact_added: "Contact added — select it to open the chat".into(),
        select_conversation: "Select a conversation".into(),
        type_message: "Type a message".into(),
        send: "Send".into(),
        paste_encrypted: "Paste encrypted message here".into(),
        receive_pasted: "Receive pasted".into(),
        unlock: "Unlock SafeChat".into(),
        create_profile: "Create a SafeChat profile".into(),
        unlock_help: "Select a profile and enter its password.".into(),
        create_help: "Create a separate encrypted identity for another user.".into(),
        profile_name: "Profile name".into(),
        password: "Password".into(),
        confirm_password: "Confirm password".into(),
        create_profile_button: "Create profile".into(),
        unlock_profile: "Unlock profile".into(),
        back_to_profiles: "Back to profiles".into(),
        create_new_profile: "Create new profile".into(),
        fingerprint: "Fingerprint".into(),
        your_fingerprint: "Your fingerprint".into(),
        share_bundle: "Share the public bundle only through a trusted channel.".into(),
        copy_bundle: "Copy public bundle".into(),
        close: "Close".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::ui_text;

    #[test]
    fn english_is_the_default_locale() {
        assert_eq!(ui_text("en").send, "Send");
        assert_eq!(ui_text("unknown").send, "Send");
    }

    #[test]
    fn russian_translates_the_public_ui_copy() {
        assert_eq!(ui_text("ru").send, "Отправить");
        assert_eq!(ui_text("rus").close, "Закрыть");
    }
}
