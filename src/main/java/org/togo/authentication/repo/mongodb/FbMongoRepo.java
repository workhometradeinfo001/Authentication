package org.togo.authentication.repo.mongodb;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.togo.authentication.entity.LongLiveTokenEntity;

@Repository
public interface FbMongoRepo extends MongoRepository<LongLiveTokenEntity, String> {
}
