// SPDX-License-Identifier: MIT
use enzimos_policy::memory;
use serde_json::{Value, json};

/// A simulated earlyoom unit: restart re-reads the published document; a
/// `broken` preset never confirms (as when the running task cannot be bound).
struct Unit {
    document: Vec<u8>,
    running: Option<String>,
    broken: Vec<&'static str>,
    refuse: bool,
    fail_restore: bool,
    polls_to_start: u32,
    polls: u32,
    budget: u32,
    log: Vec<String>,
}
impl Unit {
    fn new(mode: &str) -> Self {
        Self {
            document: doc(mode),
            running: (mode != "off").then(|| mode.to_owned()),
            broken: vec![],
            refuse: false,
            fail_restore: false,
            polls_to_start: 2,
            polls: 0,
            budget: 0,
            log: vec![],
        }
    }
    fn mode(&self) -> String {
        serde_json::from_slice::<Value>(&self.document).unwrap()["mode"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
fn doc(mode: &str) -> Vec<u8> {
    enzimos_platform::json::canonical(&json!({"schema":1,"mode":mode})).unwrap()
}
impl memory::Effects for Unit {
    fn authorize(&mut self) -> enzimos_platform::Result<()> {
        self.log.push("authorize".into());
        if self.refuse {
            return Err(enzimos_platform::Error("not-authorized".into()));
        }
        Ok(())
    }
    fn recheck(&mut self) -> enzimos_platform::Result<()> {
        Ok(())
    }
    fn publish(&mut self, body: &[u8]) -> enzimos_platform::Result<()> {
        if self.fail_restore && self.log.iter().any(|e| e.starts_with("publish")) {
            return Err(enzimos_platform::Error("publish refused".into()));
        }
        self.log
            .push(format!("publish {}", String::from_utf8_lossy(body)));
        self.document = body.into();
        Ok(())
    }
    fn restart(&mut self) -> enzimos_platform::Result<()> {
        self.log.push("restart".into());
        self.polls = 0;
        let mode = self.mode();
        self.running = (mode != "off").then_some(mode);
        Ok(())
    }
    fn state(&mut self) -> enzimos_platform::Result<Value> {
        let starting = self.polls < self.polls_to_start;
        Ok(match &self.running {
            None => json!({"ActiveState":"inactive","EffectiveMode":null}),
            // The launcher PID is not earlyoom yet: active, mode unknown.
            Some(_) if starting => json!({"ActiveState":"active","EffectiveMode":null}),
            Some(m) if self.broken.contains(&m.as_str()) => {
                json!({"ActiveState":"active","EffectiveMode":null})
            }
            Some(m) => json!({"ActiveState":"active","EffectiveMode":m}),
        })
    }
    fn begin(&mut self) {
        self.budget = 10;
    }
    fn wait(&mut self) -> bool {
        self.polls += 1;
        self.budget = self.budget.saturating_sub(1);
        self.budget > 0
    }
}
#[test]
fn refused_authorization_touches_nothing() {
    let mut unit = Unit::new("balanced");
    unit.refuse = true;
    let before = unit.document.clone();
    assert!(memory::transition("responsive", &before, &mut unit).is_err());
    assert_eq!(unit.log, ["authorize"]);
    assert_eq!(unit.document, before);
    assert_eq!(unit.running.as_deref(), Some("balanced"));
    // Invalid requested or recorded documents are refused before authorization.
    let mut unit = Unit::new("balanced");
    assert!(memory::transition("turbo", &before, &mut unit).is_err());
    assert!(memory::transition("off", b"{\"mode\":\"x\"}", &mut unit).is_err());
    assert!(unit.log.is_empty());
}
#[test]
fn unconfirmed_change_rolls_back_and_reports_what_was_restored() {
    let mut unit = Unit::new("balanced");
    unit.broken = vec!["responsive"];
    let before = unit.document.clone();
    let error = memory::transition("responsive", &before, &mut unit).unwrap_err();
    assert!(
        error.0.contains("did not take effect")
            && error.0.contains("balanced restored and confirmed running"),
        "{}",
        error.0
    );
    assert_eq!(unit.document, before);
    assert_eq!(unit.running.as_deref(), Some("balanced"));
    assert_eq!(unit.log.iter().filter(|e| *e == "restart").count(), 2);

    // Nothing can be confirmed: the document is still restored, the error says so.
    let mut unit = Unit::new("balanced");
    unit.broken = vec!["responsive", "balanced"];
    let error = memory::transition("responsive", &before, &mut unit).unwrap_err();
    assert!(
        error
            .0
            .contains("balanced restored but not confirmed running"),
        "{}",
        error.0
    );
    assert_eq!(unit.document, before);

    // Restoration itself fails: reported, never claimed.
    let mut unit = Unit::new("balanced");
    unit.broken = vec!["responsive"];
    unit.fail_restore = true;
    let error = memory::transition("responsive", &before, &mut unit).unwrap_err();
    assert!(error.0.contains("could not be restored"), "{}", error.0);
}
