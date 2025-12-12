use base64::{Engine, engine::general_purpose};
use pasetors::{
    keys::{AsymmetricKeyPair, Generate},
    version4::V4,
};
use rbatis::{RBatis, rbdc::DateTime};

use crate::{config::create_repo, models::KeyPair};

pub struct KeyRepository {
    rb: RBatis,
}

impl KeyRepository {
    pub async fn new(connection_string: &str) -> Result<Self, String> {
        let rb = create_repo(connection_string)
            .await
            .map_err(|error| error)?;
        Ok(Self { rb })
    }

    // get stored key pair if not null create a new key pair
    pub async fn get_key_pair(&self) -> Result<KeyPair, String> {
        let key_pair: Option<KeyPair> = self
            .rb
            .query_decode(
                "SELECT private_key, public_key, created_at FROM key_pair ORDER BY created_by DESC",
                vec![],
            )
            .await
            .map_err(|error| error.to_string())?;
        match key_pair {
            Some(keys) => Ok(keys),
            None => self.create_key_pair().await.map_err(|error| error),
        }
    }

    // create key pair
    pub async fn create_key_pair(&self) -> Result<KeyPair, String> {
        let kp = AsymmetricKeyPair::<V4>::generate().map_err(|error| error.to_string())?;
        let private_key = general_purpose::STANDARD.encode(kp.secret.as_bytes());
        let public_key = general_purpose::STANDARD.encode(kp.public.as_bytes());
        let data = KeyPair {
            private_key: private_key,
            public_key: public_key,
            created_at: DateTime::now(),
        };
        let _result = KeyPair::insert(&self.rb, &data)
            .await
            .map_err(|error| error.to_string())?;

        Ok(data)
    }

    // delete all stored keys in the database
    pub async fn delete_key_pair(&self) -> Result<(), String> {
        let _ = self
            .rb
            .exec("DELETE FROM key_pair", vec![])
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    // if key is key is older than tim days delete and create an new one
    pub async fn rotate_key_pair(&self, days_to_live: u64) -> Result<KeyPair, String> {
        // Get latest key age in days (if any)
        let elapsed_days: Option<u64> = self
            .rb
            .query_decode(
                "SELECT DATE_PART('day', NOW() - created_at) 
             FROM key_pair 
             ORDER BY created_at DESC LIMIT 1",
                vec![],
            )
            .await
            .map_err(|e| e.to_string())?;

        // Should we rotate?
        let should_rotate = match elapsed_days {
            Some(days) => days >= days_to_live,
            None => false,
        };

        if should_rotate {
            self.delete_key_pair().await.map_err(|e| e.to_string())?;
            return self.create_key_pair().await.map_err(|e| e.to_string());
        }

        // Get existing key pair
        let existing: Option<KeyPair> = self
            .rb
            .query_decode(
                "SELECT * FROM key_pair ORDER BY created_at DESC LIMIT 1",
                vec![],
            )
            .await
            .map_err(|e| e.to_string())?;

        // Return existing or create new
        match existing {
            Some(k) => Ok(k),
            None => self.create_key_pair().await.map_err(|e| e.to_string()),
        }
    }
}
