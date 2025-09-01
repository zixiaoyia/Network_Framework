using UnityEngine;

public class LocalPlayerController : MonoBehaviour
{
    private NetworkManager _network;
    private int _playerId;

    private const int MSG_MOVE_REQUEST = 3;

    public void Init(NetworkManager network, int playerId)
    {
        _network = network;
        _playerId = playerId;
    }

    void Update()
    {
        float h = Input.GetAxis("Horizontal");
        float v = Input.GetAxis("Vertical");
        var move = 5f * Time.deltaTime * new Vector3(h, 0, v);
        transform.position += move;

        if (move != Vector3.zero && _network != null)
        {
            _ = _network.SendMsgAsync(MSG_MOVE_REQUEST, new
            {
                playerId = _playerId,
                transform.position.x,
                transform.position.y,
                transform.position.z
            });
        }
    }
}
