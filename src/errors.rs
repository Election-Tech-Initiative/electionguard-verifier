pub struct ErrorContext<'a> {
    errs: &'a mut Vec<String>,
    prefix: String,
}

impl<'a> ErrorContext<'a> {
    pub fn new(errs: &'a mut Vec<String>) -> ErrorContext<'a> {
        ErrorContext {
            errs,
            prefix: String::new(),
        }
    }

    pub fn check(&mut self, cond: bool, msg: &str) {
        if !cond {
            self.errs.push(format!("{}{}", self.prefix, msg));
        }
    }

    pub fn scope<'b>(&'b mut self, desc: &str) -> ErrorContext<'b> {
        ErrorContext {
            errs: &mut *self.errs,
            prefix: format!("{}in {}: ", self.prefix, desc),
        }
    }
}
