package br.ufg.inf.fs.amazonsqs;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Implementação do processo de assinatura, versão 4, de requisição
 * para acesso aos serviços da Amazon.
 * <p>O processo detalhado pode ser obtido
 * <a href="http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">aqui</a>.
 * </p>
 * <p>Este processo é dividido em tarefas: (i) criação da requisição
 * canônica (@see #canonicalRequest); (ii) criação da sequência de caracteres
 * a ser assinada (@see #stringToSign); e (iii) criação da assinatura
 * ().</p>
 *
 * @author Fábio Nogueira de Lucena
 */
public class AssinaturaV4 {

    /**
     * Região correspondente à São Paulo.
     */
    private final String REGION = "sa-east-1";

    /**
     * Chave secreta a partir da qual a chave empregada
     * para a assinatura da requisição será derivada.
     */
    private String chaveSecreta;

    /**
     * URL do serviço a ser utilizado.
     */
    private String url;

    /**
     * Host que hospeda o serviço para o qual uma requisição
     * é realizada.
     */
    private String host;

    /**
     * Data a ser utilizada para a submissão da requisição.
     * Observe que é obtida quando uma instância é criada.
     */
    private ZonedDateTime instante = ZonedDateTime.now(ZoneOffset.UTC);

    /**
     * Região na qual o serviço é oferecido. Por padrão o valor
     * adotado é "sa-east-1", que correspondente a São Paulo.
     */
    private String regiao = REGION;

    /**
     * Nome do serviço para o qual a requisição
     * será assinada.
     */
    private String servico = "não fornecido";

    /**
     * Conteúdo do corpo da requisição HTTP.
     */
    private String payload;

    /**
     * Cria uma instância de {@link br.ufg.inf.fs.amazonsqs.AssinaturaV4}
     * a partir do <i>endpoint</i> do serviço para o qual uma requisição
     * correspondente deverá ser assinada.
     * <p>O objeto desta classe deverá ser devidamente configurado antes
     * que o método @see #assinatura seja chamado.</p>
     * @param endpoint
     */
    public AssinaturaV4(String endpoint) {
        this.url = endpoint;
    }

    /**
     * Define <i>host</i> onde se encontra o serviço a ser fornecido.
     *
     * @param host Endereço do serviço a ser utilizao.
     * @return Instância que recebe esta mensagem.
     */
    public AssinaturaV4 host(String host) {
        this.host = host;
        return this;
    }

    /**
     * Define a chave secreta a ser empregada para a definição da
     * chave a ser, de fato, empregada no processo de assinatura
     * da requisição.
     *
     * @param chaveSecreta Chave secreta a ser empregada.
     * @return O objeto que recebe a requisição.
     */
    public AssinaturaV4 chave(String chaveSecreta) {
        this.chaveSecreta = chaveSecreta;

        return this;
    }

    /**
     * Monta <i>payload</i> da requisição a partir do corpo
     * correspondente.
     *
     * @param corpoHttp Corpo da requisição do qual o <i>payload</i>
     *                  será produzido.
     * @return O <i>payload</i> da requisição. Se o corpo fornecido
     * for <c>null</c>, então a sequência vazia será empregada. Caso
     * contrário, o argumento fornecido será o <i>payload</i> da
     * requisição.
     */
    public AssinaturaV4 payload(String corpoHttp) {
        payload = corpoHttp != null ? corpoHttp : "";
        return this;
    }

    /**
     * Define a região para a qual a requisição será
     * assinada.
     *
     * @param regiao A região a ser utilizada. A região é
     *               uma sequência de caracteres específica para um dado serviço.
     *               Consulte <a href="http://docs.aws.amazon.com/general/latest/gr/rande.html">
     *               Regions and Endpoints</a> para detalhes.
     * @return O próprio objeto que recebe esta mensagem.
     */
    public AssinaturaV4 regiao(String regiao) {
        this.regiao = regiao;

        return this;
    }

    /**
     * Define o nome do serviço para o qual a requisição correspondente
     * é assinada.
     *
     * @param servico Nome do serviço, por exemplo, "sqs" e "iam".
     * @return O objeto que recebeu esta mensagem.
     */
    public AssinaturaV4 servico(String servico) {
        this.servico = servico;

        return this;
    }

    /**
     * Obtém a requisição canônica.
     * <p>Detalhes do processo estão disponíveis em
     * <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html">aqui</a>.
     * </p>
     *
     * @return Requisição canônica a ser produzida
     * no processo de produção de assinatura, versão 4,
     * de requisição a ser submetida para a Amazon.
     */
    public String canonicalRequest() {
        return httpMethod() + "\n" +
                canonicalUri(url, host) + "\n" +
                canonicalQueryString() + "\n" +
                canonicalHeaders() + "\n" +
                signedHeaders() + "\n" +
                toHex(sha256(payload));
    }

    public String hashedCanonicalRequest() {
        String requisicaoCanonica = canonicalRequest();
        byte[] hash = sha256(requisicaoCanonica);

        return toHex(hash);
    }

    /**
     * Obtém a sequência de caracteres que será empregada para a produção
     * da assinatura.
     * <p>Nesta implementação usa-se o algoritmo de <i>hash</i>
     * SHA256 e, por conseguinte, o algoritmo a ser utilizado na montagem
     * da sequência a ser assinada é "AWS-HMAC-SHA256".</p>
     * <p>A montagem da sequência a ser assinada é a segunda tarefa do
     * processo de assinatura. Consulte
     * <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html">
     * aqui</a> para detalhes.</p>
     *
     * @return Sequência de caracteres que será assinada.
     */
    public String stringToSign() {
        return "AWS4-HMAC-SHA256\n" +
                dataCredentialScope() + "\n" +
                credentialScope() + "\n" +
                hashedCanonicalRequest();
    }

    public String credentialScope() {
        return dataEmOitoDigitos() + "/" + regiao + "/" + servico + "/aws4_request";
    }

    /**
     * Obtém sequência de caracteres, no formato YYYYMMDD, a
     * partir do instante da assinatura.
     * Veja <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html">
     * Date handling</a> para detalhes.
     *
     * @return Data no formato de 8 dígitos exigida no processo de
     * montagem da assinatura.
     * @see #dataCredentialScope()
     */
    public String dataEmOitoDigitos() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        return instante.format(dtf);
    }

    /**
     * Data no formato UTC, exigido pelo processo de assinatura.
     * Veja <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html">
     * Date handling</a> para detalhes.
     *
     * @return Data no formato exigido pelo processo de assinatura a ser
     * empregado para montagem do <i>credential scope</i>.
     * @see #dataEmOitoDigitos()
     */
    public String dataCredentialScope() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHMMSS'Z'");

        return instante.format(dtf);
    }

    /**
     * Headers que fazem parte da assinatura: content-type, host
     * e x-amz-date. Observe que o retorno deste método está em
     * conformidade com o método @see canonicalHeaders.
     *
     * @return Headers que fazem parte da assinatura.
     */
    public static String signedHeaders() {
        return "content-type;host;x-amz-date";
    }

    /**
     * Três headers são empregados para requisições ao Amazon SQS:
     * content-type, host e x-amz-date. Observe que devem ser fornecidos
     * nesta ordem.
     *
     * @return Headers empregados pela requisição enviada ao Amazon SQS,
     * já na forma canônica esperada. Observe que termina com
     * "\n".
     */
    public String canonicalHeaders() {
        final String H1 = "content-type:application/x-www-form-urlencoded\n";
        final String H2 = String.format("host:%s\n", host);

        final String H3 = String.format("x-amz-date:%s\n", dataCredentialScope());

        return H1 + H2 + H3;
    }

    /**
     * A query string, versão canônica, da requisição.
     *
     * @return Sequência vazia. As requisições serão todas
     * empregando o método POST, ou seja, não conterão
     * parâmetros na requisição.
     */
    private static String canonicalQueryString() {
        return "";
    }

    /**
     * Obtém o "path" absoluto da URL da fila.
     *
     * @param queueUrl A URL da fila. Necessariamente deve terminar pelo
     *                 caractere "/".
     * @param host     O servidor a ser utilizado (parte do parâmetro anterior).
     * @return O "path" absoluto, ou seja, retira-se o "host" e o que segue
     * o caractere ? (inclusive este), da URL da fila. Se for vazio, então
     * use a "/" como resposta.
     */
    public static String canonicalUri(String queueUrl, String host) {
        int inicio = queueUrl.indexOf(host) + host.length();
        String absolutePath = queueUrl.substring(inicio);
        return absolutePath.length() == 0 ? "/" : absolutePath;
    }

    /**
     * Método a ser empregado para requisições ao Amazon SQS.
     * Esta classe faz uso exclusivo do método POST.
     *
     * @return POST.
     */
    private static String httpMethod() {
        return "POST";
    }

    /**
     * Obtém o valor <i>hash</i> dos dados, com base na
     * senha fornecida, empregando o
     * algoritmo HMACSHA256.
     *
     * @param chave A chave a ser empregada para a assinatura.
     * @param dados Os dados para os quais a assinatura é desejada.
     * @return A assinatura da sequência fornecida, obtida com o uso
     * da chave.
     * @throws Exception
     */
    static byte[] HmacSHA256(byte[] chave, String dados) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(chave, algorithm));

        return mac.doFinal(dados.getBytes("UTF8"));
    }

    static byte[] getSigningKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(kSecret, dateStamp);
        byte[] kRegion = HmacSHA256(kDate, regionName);
        byte[] kService = HmacSHA256(kRegion, serviceName);
        return HmacSHA256(kService, "aws4_request");
    }

    /**
     * Obtém o valor de hash da entrada fornecida empregando
     * o algoritmo SHA256.
     *
     * @param entrada A entrada cujo valor de hash é desejado.
     * @return O valor de hash, SHA256, para a entrada fornecida.
     * Retorna null caso o valor de hash não seja obtido de
     * forma satisfatória.
     */
    public static byte[] sha256(String entrada) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(entrada.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * Converte o vetor de bytes na sequência hexadecimal
     * correspondente usando apenas letras minúsculas.
     * Consulte detalhes em
     * <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html">
     * aqui</a>.
     *
     * @param entrada Vetor de bytes cuja sequência em hexa é desejada.
     * @return Sequência hexadecimal correspondente ao vetor de bytes.
     */
    public static String toHex(byte[] entrada) {
        StringBuilder sb = new StringBuilder();

        for (byte b : entrada) {
            sb.append(String.format("%02x", b & 0xff));
        }

        return sb.toString();
    }

    /**
     * Produz a assinatura correspondente para uma dada requisição.
     * <p>A assinatura produzida por este método segue as orientações
     * estabelecidas para a tarefa 3, disponível
     * <a href="http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html">
     *     aqui</a>.</p>
     * @return A sequência a ser empregada como a assinatura da
     * requisição.
     * @throws Exception
     */
    public String assinatura() throws Exception {
        byte[] derivedSigningKey = getSigningKey(chaveSecreta, dataEmOitoDigitos(), regiao, servico);
        byte[] assinatura = HmacSHA256(derivedSigningKey, stringToSign());

        return toHex(assinatura);
    }
}
