//Inicio MQTT.
import verificarToken from './verificarToken';
const dotenv = require('dotenv');
dotenv.config();
const mqtt = require('mqtt');
const clientId = `mqtt_${Math.random().toString(16).slice(3)}`

const connectUrl = `${process.env.HOST}:${process.env.PORT_MOSQUITTO}`

const client = mqtt.connect(connectUrl, {
    clientId,
    clean: true,
    connectTimeout: 4000,
    reconnectPeriod: 1000,
})
  
client.on('connect', () => {
    console.log('Connected')
    client.subscribe("/id/limpiar");
    client.subscribe("/listo");
    client.subscribe("/login/auth");
})


const jwt = require('jsonwebtoken');
const express = require("express");
const bcrypt = require('bcrypt');
const bodyParser = require("body-parser");

const app = express()

//cargo entorno y corro app
let port = process.env.PORT || 3000;
app.use(express.json());
app.listen(port, () => {
    console.log("Server Listening on PORT:", port); 
});


app.post("/user/login", async (req, res) => {

  try{
    client.publish("/login", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
    });

  }catch{
    res.send("Error a publicar en mqtt, intente nuevamente");
    res.status(409).send("Conflicto");
  }

  let nodeRes;

  try{
    nodeRes = await waitForValidation();
  }catch{
    res.status(401).send("Usuario no encontrado, intente nuevamente");
    return;
  }

  
  // encriptado contraseña...
  bcrypt.compare(req.body.contrasenia, nodeRes.contrasenia, (err, result) => {
    if (err) {
      console.error('Error al comparar las contraseñas:', err);
      res.status(409).send("Conflicto");
    
    } else if (result) {
      console.log('Las contraseñas coinciden. El usuario puede iniciar sesión.');
      let jwtSecretKey = process.env.JWT_SECRET_KEY;
      let data = {
        time: Date(),
        userId: nodeRes.id,
      }
  
      const token = jwt.sign(data, jwtSecretKey);
      const parametros = {
        token: token,
        id: nodeRes.id
      }
      try{
        client.publish("/token", JSON.stringify(parametros), { qos: 0, retain: false }, (error) => {
          if (error) {
            console.log(error)
            console.error(error)
          }
        });
    
      }catch{
        res.send("Error a publicar en mqtt, intente nuevamente");
        res.status(409).send("Conflicto");
      }
    
      res.status(200).json(token);
      // Aquí es donde normalmente procederías con la lógica para iniciar sesión o permitir el acceso del usuario
    } else {
      console.log('Las contraseñas no coinciden. El usuario no puede iniciar sesión.');
      res.status(404).send("Contraseña incorrecta");
      // Aquí es donde normalmente mostrarías un mensaje de error al usuario o tomarías alguna acción adicional
    }
  }); //TODO guardar token en bd. Mandar x mqtt y almacenar con ID.    
});

const waitForValidation = () => {
    
  return new Promise((resolve, reject) => {
    client.on('message', (topic, message) => {
      if (topic === '/login/auth') {
        try{
          jsonString = message.toString().match(/\[(.*?)\]/);
          const response = JSON.parse(jsonString[1]);
          if(response.id !== null){
            resolve(response);
          } else {
            
            reject();
          }
        }catch (e){
          reject();
        }
      }
    });
  });

};




app.get("/status", (req, res) => {
  
  let contra;

  bcrypt.hash(req.body.contrasenia, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error al hashear la contraseña:', err);
    } else {
      console.log('Contraseña hasheada:', hashedPassword);
      contra = hashedPassword;
    }
  });
  
  const status = {
      Status: "Running"
   };
   
   res.send(contra);
});

const waitForId = () => {
    return new Promise((resolve, reject) => {
      client.on('message', (topic, message) => {
        if (topic === '/listo') {
          jsonString = message.toString().match(/\[(.*?)\]/);
          const response = JSON.parse(jsonString[1]);
          resolve(response);
        }
      });
    });
};



app.post('/identificacion/recipiente', async (req, res) => {
    try {
      // Publicar el cuerpo en un topic MQTT
      client.publish("/inicio/carga", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
        if (error) {
          console.log(error)
          console.error(error)
        }
      });
  
      // Esperar hasta recibir la respuesta del MQTT
      const response = await waitForId();
  
      // Enviar la respuesta al cliente
      res.status(200).json(response);
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send('Error en el servidor');
    }
});

app.post('/control/inicio', async (req, res) => {
    try{

    
    client.publish("/control/inicio", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
        if (error) {
          console.log(error)
          console.error(error)
        }
    });
    }catch (error){
        console.error('Error:', error);
        res.status(500).send('Error en el servidor');
    } 
    
    res.status(200).send("Control Iniciado con Exito");

});

app.post('/test', async (req, res) => {
  try{

  
  client.publish("/empezar/control", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
  });
  }catch (error){
      console.error('Error:', error);
      res.status(500).send('Error en el servidor');
  }    

});



client.on('message',function(topic, message, packet){
    
    if(topic === '/id/limpiar'){
        jsonString = message.toString().match(/\[(.*?)\]/); //pregunta

        console.log(jsonString[1] == '');
        
        if(jsonString[1] !== ''){
            jsonParsed = JSON.parse(jsonString[1]);
            console.log(jsonParsed);
            client.publish("/id/recipiente", JSON.stringify(jsonParsed)  , { qos: 0, retain: false }, (error) => {
                if (error) {
                    console.log(error)
                    console.error(error)
                    }
                })
        }
        
    }



    
});

const verificarToken = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }

  // Eliminamos el prefijo "Bearer " del token
  const tokenSinBearer = token.replace('Bearer ', '');

  try {
    const datosToken = jwt.verify(tokenSinBearer, process.env.JWT_SECRET_KEY); //DEVUELVE ID Y DATE.
    req.usuario = datosToken; // Si deseas acceder a los datos del usuario autenticado desde las rutas, puedes guardarlos en req.usuario
    return datosToken;
  } catch (error) {
    return res.status(401).json({ mensaje: 'Token inválido.' });
  }
};