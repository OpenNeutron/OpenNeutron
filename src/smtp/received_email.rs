use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub raw_data: Vec<u8>,
    pub content: String,
    pub headers: HashMap<String, String>,
    
    
    pub dkim_status: String,
    pub is_e2ee: bool,
}

impl Email {
    pub fn new() -> Self {
        Email {
            from: String::new(),
            to: Vec::new(),
            raw_data: Vec::new(),
            content: String::new(),
            headers: HashMap::new(),
            dkim_status: String::new(),
            is_e2ee: false,
        }
    }

    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        let mut email_string = "=================\r\n".to_string();
        email_string.push_str(&format!("From: {}\r\n", self.from));
        for recipient in &self.to {
            email_string.push_str(&format!("To: {}\r\n", recipient));
        }
        email_string.push_str(&format!("Headers: \r\n"));
        for (key, value) in &self.headers {
            email_string.push_str(&format!("{}: {}\r\n", key, value));
        }
        email_string.push_str(&format!("\r\n{}", self.content));
        email_string.push_str("=================\r\n");
        return email_string;
    }
}
