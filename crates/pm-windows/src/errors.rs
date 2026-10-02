//! Human-readable explanations for WinDivert start-up failures.

/// Explains a Win32 error code returned by `WinDivertOpen`.
pub fn explain_open_error(code: i32) -> String {
    let hint = match code {
        2 => "не найден драйвер WinDivert64.sys — положите его рядом с программой",
        5 => "нет прав администратора — запустите программу от имени администратора",
        87 => "некорректный фильтр WinDivert",
        577 => {
            "подпись драйвера не прошла проверку (проверьте целостность файлов WinDivert или отключите режим проверки подписи в стороннем ПО)"
        }
        654 => "предыдущая версия драйвера WinDivert ещё загружена — перезагрузите компьютер",
        1060 => "служба драйвера WinDivert не установлена",
        1275 => "загрузка драйвера заблокирована (антивирус, античит или политика безопасности)",
        1753 => "служба Base Filtering Engine не запущена",
        _ => "неизвестная ошибка",
    };
    format!("не удалось запустить перехват WinDivert (код {code}): {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_codes() {
        assert!(explain_open_error(5).contains("администратора"));
        assert!(explain_open_error(2).contains("WinDivert64.sys"));
        assert!(explain_open_error(1275).contains("заблокирована"));
        assert!(explain_open_error(42).contains("код 42"));
        for code in [87, 577, 654, 1060, 1753] {
            assert!(!explain_open_error(code).contains("неизвестная"), "{code}");
        }
    }
}
