/**
 * Biblioteca que contem as api de acesso
 * aos serviços da AWS
 * @var AWS
 */
const AWS = require('aws-sdk');

/**
 * Serviço de banco de dados DynamoDB
 * @var dynamoDB
 */
const dynamoDB = new AWS.DynamoDB.DocumentClient();

/**
 * Função responsável por realizar a atualização
 * do token de acesso ao email do usuário
 * @param {object} oAuth2Client
 * @param {string} sEmail
 * @param {object} oTokens 
 * @returns {object}
 */
const refreshAccessToken = async function (oAuth2Client, sEmail, oTokens) {

  const currentTime = Date.now();
  const expiryDate = oTokens.expiry_date;

  if (expiryDate > currentTime) {
    return oTokens;
  }

  /**
   * Configura as credênciais de acesso ao email
   * do usuário
   */
  oAuth2Client.setCredentials({
    access_token: oTokens.access_token,
    refresh_token: oTokens.refresh_token,
  });

  /**
   * Obtem as novas credênciais de autorização
   */
  const { credentials } = await oAuth2Client.refreshAccessToken();

  /**
   * Atualiza o token do email apenas com os campos necessários
   */
  await dynamoDB.update({
    TableName: 'email_tokens',
    Key: { email: sEmail },
    UpdateExpression: 'SET tokens.access_token = :newAccessToken, tokens.refresh_token = :newRefreshToken, tokens.expiry_date = :newExpiryDate',
    ExpressionAttributeValues: {
      ':newAccessToken': credentials.access_token,
      ':newRefreshToken': credentials.refresh_token,
      ':newExpiryDate': credentials.expiry_date
    },
  }).promise();

  return credentials;
}

const base64Decode = function (base64) {
  return Buffer.from(base64, 'base64').toString('utf-8');
}

const getEmailBodyText = function (parts) {

  for (const keyParts in parts) {
    const part = parts[keyParts];

    if (part.mimeType == 'text/plain') {
      return base64Decode(part.body.data);
    }
  }

  return null;
}

const getEmailBodyHTML = function (parts) {
  for (const keyParts in parts) {

    const part = parts[keyParts];

    if (part.mimeType == 'text/html') {
      return base64Decode(part.body.data);
    }
  }

  return null;
}

const getParameterStore = async function (name, WithDecryption = false)  {
  /**
   * Instancia serviço AWS SSM para carregar as credenciais
   * @var ssm
   */
  const ssm = new AWS.SSM();

  /**
   * Consulta as credenciais de acesso aos serviços do Google no AWS SSM
   * @var response
   */
  const response = await ssm.getParameter({
    Name: name,
    WithDecryption: WithDecryption
  }).promise();

  return response.Parameter.Value;
}

module.exports = {
  refreshAccessToken,
  getEmailBodyText,
  getEmailBodyHTML,
  base64Decode,
  getParameterStore
}