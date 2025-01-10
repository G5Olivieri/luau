from locust import HttpUser, task


class Client(HttpUser):
    def on_start(self):
        response = self.client.post(
            "/",
            json={
                "name": {"default": "client", "pt_BR": "client"},
                "redirect_uris": ["https://client-app.com/oauth/callback"],
            },
        )
        data = response.json()
        self.id = data["id"]

    @task
    def get_client(self):
        with self.client.rename_request(r"/{id}"):
            self.client.get("/" + self.id)

    # @task
    # def basic_usage(self):
    #     response = self.client.post(
    #         "/",
    #         json={
    #             "name": {"default": "client", "pt_BR": "client"},
    #             "redirect_uris": ["https://client-app.com/oauth/callback"],
    #         },
    #     )
    #     data = response.json()
    #     with self.client.rename_request(r"/{id}"):
    #         for i in range(100):
    #             self.client.get("/" + data["id"])

    #         for i in range(30):
    #             self.client.put(
    #                 "/" + data["id"],
    #                 json={
    #                     "name": {"default": "client", "pt_BR": "client"},
    #                     "redirect_uris": ["http://localhost:3000/callback.html"],
    #                 },
    #             )

    #         self.client.delete("/" + data["id"])
