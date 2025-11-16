from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

from networksecurity.entity.config_entity import DataIngestionConfig
from networksecurity.entity.artifact_entity import DataIngestionArtifact

import os
import sys
import numpy as np
import pandas as pd
import pymongo
from sklearn.model_selection import train_test_split
from dotenv import load_dotenv

load_dotenv()   # Load .env variables

# Load correct environment variable
MONGO_DB_URL = os.getenv("MONGO_URI")  


class DataIngestion:
    def __init__(self, data_ingestion_config: DataIngestionConfig):
        try:
            self.data_ingestion_config = data_ingestion_config
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def export_collection_as_dataframe(self):
        """
        Read data from MongoDB and convert to pandas DataFrame
        """
        try:
            database_name = self.data_ingestion_config.database_name
            collection_name = self.data_ingestion_config.collection_name

            print("\n🔍 DEBUG: Connecting to MongoDB")
            print("MONGO URI:", MONGO_DB_URL)
            print("Database:", database_name)
            print("Collection:", collection_name)

            # Connect to MongoDB
            self.mongo_client = pymongo.MongoClient(MONGO_DB_URL)
            collection = self.mongo_client[database_name][collection_name]

            count = collection.count_documents({})
            print("Documents in collection:", count)

            if count == 0:
                raise Exception("MongoDB collection is EMPTY! Cannot proceed.")

            # Fetch documents
            df = pd.DataFrame(list(collection.find()))

            if "_id" in df.columns:
                df = df.drop(columns=["_id"])

            df.replace({"na": np.nan}, inplace=True)
            return df

        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def export_data_into_feature_store(self, dataframe: pd.DataFrame):
        try:
            feature_store_file_path = self.data_ingestion_config.feature_store_file_path

            dir_path = os.path.dirname(feature_store_file_path)
            os.makedirs(dir_path, exist_ok=True)

            dataframe.to_csv(feature_store_file_path, index=False, header=True)

            return dataframe
            
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def split_data_as_train_test(self, dataframe: pd.DataFrame):
        try:
            if dataframe.shape[0] == 0:
                raise Exception("Cannot split EMPTY dataframe.")

            train_set, test_set = train_test_split(
                dataframe,
                test_size=self.data_ingestion_config.train_test_split_ratio
            )

            dir_path = os.path.dirname(self.data_ingestion_config.training_file_path)
            os.makedirs(dir_path, exist_ok=True)
            
            train_set.to_csv(self.data_ingestion_config.training_file_path,
                             index=False, header=True)

            test_set.to_csv(self.data_ingestion_config.testing_file_path,
                            index=False, header=True)

        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
        
    def initiate_data_ingestion(self):
        try:
            dataframe = self.export_collection_as_dataframe()

            print("\n📌 DATAFRAME SHAPE:", dataframe.shape)
            print(dataframe.head())

            dataframe = self.export_data_into_feature_store(dataframe)
            self.split_data_as_train_test(dataframe)

            data_ingestion_artifact = DataIngestionArtifact(
                trained_file_path=self.data_ingestion_config.training_file_path,
                test_file_path=self.data_ingestion_config.testing_file_path
            )
            return data_ingestion_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)
