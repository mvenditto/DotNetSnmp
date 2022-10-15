namespace SnmpDotNet.Transport.Targets
{
    public record CommunityTarget: AbstractTarget
    {
        public CommunityTarget()
        {

        }

        public CommunityTarget(string community)
        {
            Community = community;
        }

        public string Community
        {
            get => SecurityName;
            init => SecurityName = value;
        }
    }
}
