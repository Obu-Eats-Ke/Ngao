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
                "SELECT * FROM key_pair ORDER BY created_at DESC LIMIT 1",
                vec![],
            )
            .await
            .map_err(|error| error.to_string())?;
        if let Some(keys) = key_pair {
            
            return Ok(keys);
        } else {
            let keys = self.create_key_pair().await.map_err(|error| error)?;
            return Ok(keys);
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

    // if key is key is older than seven days delete and create an new one
    pub async fn rotate_key_pair(&self) -> Result<(), String> {
        let elaspsed_time: Option<u64> = self.rb.query_decode("SELECT DATE_PART('day', NOW() - created_at) FROM key_pair ORDER BY created_at DESC LIMIT 1", vec![]).await.map_err(|error| error.to_string())?;
        if let Some(elasped_time) = elaspsed_time {
            if elasped_time > 7u64 {
                self.delete_key_pair().await.map_err(|error| error)?;
                self.create_key_pair().await.map_err(|error| error)?;
            }
        }else{

        }
        Ok(())
    }
}
