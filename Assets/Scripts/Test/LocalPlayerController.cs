using UnityEngine;

public class LocalPlayerController : MonoBehaviour
{
    private NetworkManager _network;
    private int _playerId;

    private const float SendInterval = 1f / 20f;
    private float _lastSend;

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

        if (Time.time - _lastSend >= SendInterval && _network != null)
        {
            _lastSend = Time.time;
            _ = _network.SendUdpMoveAsync(_playerId, transform.position);
        }
    }
}
