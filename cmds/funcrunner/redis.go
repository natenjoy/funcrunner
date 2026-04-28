package main

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
)

func SaveInventoryToRedis(key string, data []byte) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer rdb.Close()

	ctx := context.Background()
	err := rdb.Set(ctx, key, data, 0).Err()
	if err != nil {
		log.Fatalf("Error backing up inventory to redis: %s\n", err)
	}
}

func GetInventoryFromRedis(key string) map[string]Inventory {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer rdb.Close()

	ctx := context.Background()
	val, err := rdb.Get(ctx, "inventory").Result()
	if err != nil {
		log.Fatalf("Error retrieving inventory from redis: %s\n", err)
	}

	retInterface := Unmarshal([]byte(val), "inventory")
	ret, ok := retInterface.(map[string]Inventory)
	if !ok {
		log.Fatalf("Error unmarshalling inventory from redis\n")
	}
	return ret
}
