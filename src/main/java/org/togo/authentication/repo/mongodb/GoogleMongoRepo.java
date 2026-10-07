package org.togo.authentication.repo.mongodb;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.togo.authentication.entity.RefreshTokenEntity;

@Repository
public interface GoogleMongoRepo extends MongoRepository<RefreshTokenEntity, Long> {
}
