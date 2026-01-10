import app from "./app.js";
import { ENV } from "./config/env.js";


app.get("/", (req, res) => {
    res.send("<h1>Welcome to the Stardom Backend API!</h1>");
});

app.listen(ENV.PORT, () => {
  console.log(`Server running on port ${ENV.PORT}`);
});
