#[tokio::test]
async fn storage_factory_rejects_mongo_without_feature() {
    // This test intentionally runs only when the `mongo` feature is NOT enabled.
    // It ensures we fail fast with a clear error message.
    #[cfg(not(feature = "mongo"))]
    {
        let result =
            rust_oauth2_server::storage::create_storage("mongodb://localhost:27017/oauth2_test")
                .await;

        assert!(
            result.is_err(),
            "should error when mongo backend requested without feature"
        );

        let err = result.err().unwrap();

        assert!(
            err.to_string()
                .contains("built without the `mongo` feature"),
            "unexpected error: {err}"
        );
    }

    // When `mongo` is enabled, this test becomes a no-op to avoid requiring a live Mongo instance.
    #[cfg(feature = "mongo")]
    {
        // nothing
    }
}
