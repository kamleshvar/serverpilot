(function () {
  "use strict";

  const datalist = document.getElementById("repository-options");
  const repositoryInput = document.querySelector('input[name="repository_full_name"]');
  if (!datalist || !repositoryInput) {
    return;
  }

  fetch("/settings/github/repositories", {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  })
    .then(function (response) {
      if (!response.ok) {
        return null;
      }
      return response.json();
    })
    .then(function (payload) {
      if (!payload || !Array.isArray(payload.repositories)) {
        return;
      }
      payload.repositories.forEach(function (repo) {
        const option = document.createElement("option");
        option.value = repo.full_name;
        option.label = repo.private ? repo.full_name + " (private)" : repo.full_name;
        datalist.appendChild(option);
      });
    })
    .catch(function () {
      /* Repository verification remains server-side; the datalist is optional. */
    });
})();
